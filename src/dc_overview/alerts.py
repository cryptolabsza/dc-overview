"""
DC Overview Alerts Module

Handles sending alerts to the CryptoLabs Alert API for push notifications
to the CryptoLabs app, email, and web browser.

This module is prepared for future integration with the CryptoLabs Alert System.
Currently, it logs alerts locally. Once the Alert API is deployed, this module
will send alerts via HTTP POST to the centralized notification service.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Supported alert types for DC Overview."""
    EXPORTER_DOWN = "exporter_down"
    EXPORTER_FAILED = "exporter_failed"
    DEPLOYMENT_FAILED = "deployment_failed"
    WORKER_UNREACHABLE = "worker_unreachable"
    HIGH_TEMPERATURE = "high_temperature"
    GPU_ERROR = "gpu_error"
    CONTAINER_UNHEALTHY = "container_unhealthy"


@dataclass
class Alert:
    """Represents an alert to be sent."""
    alert_type: str
    severity: str
    title: str
    message: str
    server_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "dc-overview"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for API payload."""
        return {
            "source": self.source,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "server_id": self.server_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "metadata": self.metadata,
        }


class AlertManager:
    """Manages alert sending with rate limiting and queuing.
    
    This class handles:
    - Rate limiting (prevents alert spam)
    - Alert queuing (for reliable delivery)
    - Deduplication (prevents duplicate alerts)
    
    Currently operates in "log-only" mode until the CryptoLabs Alert API
    is deployed and configured.
    """
    
    def __init__(self):
        self._config = None
        self._rate_limit_cache: Dict[str, datetime] = {}
        self._lock = threading.Lock()
        self._queue: List[Alert] = []
        self._queue_processor: Optional[threading.Thread] = None
        self._running = False
    
    def configure(self, config):
        """Configure the alert manager with notification settings.
        
        Args:
            config: NotificationConfig instance from config module
        """
        self._config = config
        
        if config.enabled:
            logger.info("DC Overview Alert System enabled")
            if config.cryptolabs_api_key:
                logger.info("CryptoLabs API key configured")
            else:
                logger.warning("Alert system enabled but no API key configured")
        else:
            logger.debug("DC Overview Alert System disabled")
    
    def start(self):
        """Start the background queue processor."""
        if self._running:
            return
        
        self._running = True
        self._queue_processor = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="DCOverviewAlertProcessor"
        )
        self._queue_processor.start()
        logger.debug("Alert queue processor started")
    
    def stop(self):
        """Stop the background queue processor."""
        self._running = False
        if self._queue_processor:
            self._queue_processor.join(timeout=5)
        logger.debug("Alert queue processor stopped")
    
    def send_alert(
        self,
        alert_type: str,
        title: str,
        message: str,
        server_id: str,
        severity: str = "warning",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send an alert to the CryptoLabs Alert API.
        
        Args:
            alert_type: Type of alert (exporter_down, deployment_failed, etc.)
            title: Short alert title
            message: Detailed alert message
            server_id: Identifier for the server/worker
            severity: Alert severity (info, warning, critical)
            metadata: Additional data to include with the alert
            
        Returns:
            True if alert was queued/sent, False if rate limited or disabled
        """
        # Check if notifications are configured and enabled
        if not self._config or not self._config.enabled:
            logger.debug(f"Alert not sent (disabled): {alert_type} - {title}")
            return False
        
        # Check if this alert type is enabled
        if not self._config.is_alert_type_enabled(alert_type):
            logger.debug(f"Alert type disabled: {alert_type}")
            return False
        
        # Check rate limiting
        if self._is_rate_limited(alert_type, server_id):
            logger.debug(f"Alert rate limited: {alert_type} for {server_id}")
            return False
        
        # Create alert
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            server_id=server_id,
            metadata=metadata or {},
        )
        
        # Log the alert (always, for debugging)
        logger.info(
            f"[ALERT] {severity.upper()}: {alert_type} - {title} "
            f"(server: {server_id})"
        )
        
        # Update rate limit cache
        self._update_rate_limit(alert_type, server_id)
        
        # Queue for sending (when API is available)
        self._queue_alert(alert)
        
        return True
    
    def send_deployment_failed_alert(
        self,
        server_id: str,
        server_name: str,
        component: str,
        error: str
    ) -> bool:
        """Convenience method for deployment failure alerts."""
        return self.send_alert(
            alert_type=AlertType.DEPLOYMENT_FAILED.value,
            severity="critical",
            title=f"Deployment failed on {server_name}",
            message=f"Failed to deploy {component}: {error}",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "component": component,
                "error": error,
            }
        )
    
    def send_worker_unreachable_alert(
        self,
        server_id: str,
        server_name: str,
        reason: str = "SSH connection failed"
    ) -> bool:
        """Convenience method for worker unreachable alerts."""
        return self.send_alert(
            alert_type=AlertType.WORKER_UNREACHABLE.value,
            severity="critical",
            title=f"Worker {server_name} unreachable",
            message=reason,
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "reason": reason,
            }
        )
    
    def send_exporter_failed_alert(
        self,
        server_id: str,
        server_name: str,
        exporter_name: str,
        error: str
    ) -> bool:
        """Convenience method for exporter failure alerts."""
        return self.send_alert(
            alert_type=AlertType.EXPORTER_FAILED.value,
            severity="warning",
            title=f"Exporter failed on {server_name}",
            message=f"{exporter_name} failed: {error}",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "exporter": exporter_name,
                "error": error,
            }
        )
    
    def send_container_unhealthy_alert(
        self,
        server_id: str,
        server_name: str,
        container_name: str,
        status: str
    ) -> bool:
        """Convenience method for container health alerts."""
        return self.send_alert(
            alert_type=AlertType.CONTAINER_UNHEALTHY.value,
            severity="warning",
            title=f"Container unhealthy on {server_name}",
            message=f"{container_name}: {status}",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "container": container_name,
                "status": status,
            }
        )
    
    def _is_rate_limited(self, alert_type: str, server_id: str) -> bool:
        """Check if an alert is rate limited."""
        if not self._config:
            return False
        
        key = f"{alert_type}:{server_id}"
        with self._lock:
            if key in self._rate_limit_cache:
                last_sent = self._rate_limit_cache[key]
                min_interval = timedelta(minutes=self._config.rate_limit_minutes)
                if datetime.utcnow() - last_sent < min_interval:
                    return True
        return False
    
    def _update_rate_limit(self, alert_type: str, server_id: str):
        """Update rate limit cache for an alert."""
        key = f"{alert_type}:{server_id}"
        with self._lock:
            self._rate_limit_cache[key] = datetime.utcnow()
    
    def _queue_alert(self, alert: Alert):
        """Add alert to the send queue."""
        with self._lock:
            self._queue.append(alert)
    
    def _process_queue(self):
        """Background thread to process alert queue.
        
        Currently logs alerts. When Alert API is deployed, this will
        send alerts via HTTP POST.
        """
        while self._running:
            try:
                alerts_to_send = []
                with self._lock:
                    if self._queue:
                        alerts_to_send = self._queue[:]
                        self._queue.clear()
                
                for alert in alerts_to_send:
                    self._send_to_api(alert)
                
            except Exception as e:
                logger.error(f"Error processing alert queue: {e}")
            
            # Sleep between queue checks
            time.sleep(1)
    
    def _send_to_api(self, alert: Alert):
        """Send alert to CryptoLabs Alert API.
        
        Currently a placeholder that logs the alert.
        Will be implemented when Alert API is deployed.
        """
        if not self._config or not self._config.cryptolabs_api_key:
            # No API key configured, just log
            logger.debug(f"Alert logged (no API): {alert.to_dict()}")
            return
        
        # TODO: Implement actual API call when Alert API is deployed
        # The implementation will look like:
        #
        # import requests
        # payload = alert.to_dict()
        # payload['api_key'] = self._config.cryptolabs_api_key
        # 
        # try:
        #     response = requests.post(
        #         self._config.alert_endpoint,
        #         json=payload,
        #         timeout=10,
        #         headers={'Content-Type': 'application/json'}
        #     )
        #     if response.status_code == 200:
        #         logger.debug(f"Alert sent successfully: {alert.alert_type}")
        #     else:
        #         logger.warning(f"Alert API returned {response.status_code}")
        # except Exception as e:
        #     logger.error(f"Failed to send alert to API: {e}")
        
        logger.info(
            f"[ALERT QUEUED] Would send to {self._config.alert_endpoint}: "
            f"{alert.alert_type} - {alert.title}"
        )


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


def init_alerts(config=None):
    """Initialize the alert system.
    
    Args:
        config: NotificationConfig instance, or None to use defaults
    """
    manager = get_alert_manager()
    
    if config is None:
        # Try to load from a Config instance
        try:
            from .config import NotificationConfig
            config = NotificationConfig()
        except ImportError:
            logger.warning("Could not load notification config")
            return manager
    
    manager.configure(config)
    manager.start()
    return manager


def send_alert(
    alert_type: str,
    title: str,
    message: str,
    server_id: str,
    severity: str = "warning",
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """Convenience function to send an alert.
    
    This is the main entry point for sending alerts from anywhere in
    the DC Overview codebase.
    
    Args:
        alert_type: Type of alert (exporter_down, deployment_failed, etc.)
        title: Short alert title  
        message: Detailed alert message
        server_id: Identifier for the server/worker
        severity: Alert severity (info, warning, critical)
        metadata: Additional data to include with the alert
        
    Returns:
        True if alert was queued/sent, False if rate limited or disabled
        
    Example:
        from dc_overview.alerts import send_alert
        
        send_alert(
            alert_type="deployment_failed",
            title="Exporter deployment failed",
            message="Failed to install node_exporter on worker-01",
            server_id="192.168.1.100",
            severity="critical",
            metadata={"component": "node_exporter"}
        )
    """
    return get_alert_manager().send_alert(
        alert_type=alert_type,
        title=title,
        message=message,
        server_id=server_id,
        severity=severity,
        metadata=metadata
    )
