#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pci/pci.h>
#include <signal.h>
#include <nvml.h>

int debug_flag = 0;
#define HOTSPOT_REGISTER_OFFSET 0x0002046c
#define MAX_DEVICES 32
#define VM_RETRY_INTERVAL 30  // Seconds to wait when GPUs unavailable (VM passthrough)

#define PG_SZ sysconf(_SC_PAGE_SIZE)
#define PRINT_ERROR()                                        \
      do {                                                     \
      fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
      __LINE__, __FILE__, errno, strerror(errno));             \
      } while(0)

// GPU state enumeration
typedef enum {
    GPU_STATE_OK = 0,           // GPU accessible and healthy
    GPU_STATE_WARNING = 1,      // GPU has warnings (ECC errors, etc.)
    GPU_STATE_ERROR = 2,        // GPU has errors
    GPU_STATE_VM_PASSTHROUGH = 3,  // GPU passed to VM (on PCIe but not in NVML)
    GPU_STATE_UNAVAILABLE = 4   // GPU not responding
} GpuState;

// PCI GPU info (detected even when in VM)
typedef struct {
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t bus;
    uint8_t dev;
    uint8_t func;
    char pci_bus_id[32];
    int in_nvml;  // 1 if also found in NVML, 0 if VM passthrough
} PciGpuInfo;

PciGpuInfo pci_gpus[MAX_DEVICES];
int num_pci_gpus = 0;

// GPU architecture types
typedef enum {
    GPU_ARCH_UNKNOWN = 0,
    GPU_ARCH_CONSUMER,      // GeForce RTX 30xx/40xx - use register offsets
    GPU_ARCH_DATACENTER,    // A100/H100/A30/etc - use NVML field values
    GPU_ARCH_PROFESSIONAL   // Quadro/RTX A6000 - try both methods
} GpuArchType;

// NVML Field IDs for memory temperature (used for datacenter GPUs)
#ifndef NVML_FI_DEV_MEMORY_TEMP
#define NVML_FI_DEV_MEMORY_TEMP 140
#endif

// Detect GPU architecture type
GpuArchType detectGpuArchitecture(nvmlDevice_t device, const char* name) {
    // Check for datacenter GPUs (A100, H100, A30, etc.)
    if (strstr(name, "A100") || strstr(name, "H100") || strstr(name, "H200") ||
        strstr(name, "A30") || strstr(name, "A40") || strstr(name, "A10") ||
        strstr(name, "L40") || strstr(name, "L4")) {
        return GPU_ARCH_DATACENTER;
    }
    
    // Check for professional GPUs (RTX A6000, A5000, etc.)
    if (strstr(name, "RTX A") || strstr(name, "Quadro")) {
        return GPU_ARCH_PROFESSIONAL;
    }
    
    // Check for consumer GPUs (GeForce RTX 30xx/40xx)
    if (strstr(name, "RTX 30") || strstr(name, "RTX 40") ||
        strstr(name, "GeForce")) {
        return GPU_ARCH_CONSUMER;
    }
    
    // Try to detect via compute capability
    int major = 0, minor = 0;
    nvmlDeviceGetCudaComputeCapability(device, &major, &minor);
    
    // Hopper (H100) = 9.0, Ada = 8.9, Ampere = 8.0-8.6
    if (major >= 9) {
        return GPU_ARCH_DATACENTER;  // Hopper and later
    }
    
    return GPU_ARCH_UNKNOWN;
}

// Get memory temperature via NVML Field Values API (for datacenter GPUs like A100/H100)
int getMemoryTempViaNvml(nvmlDevice_t device, unsigned int* temp) {
    *temp = 0;
    
    // Try using nvmlDeviceGetFieldValues for MEMORY_TEMP
    nvmlFieldValue_t fieldValue;
    fieldValue.fieldId = NVML_FI_DEV_MEMORY_TEMP;
    
    nvmlReturn_t result = nvmlDeviceGetFieldValues(device, 1, &fieldValue);
    if (result == NVML_SUCCESS && fieldValue.nvmlReturn == NVML_SUCCESS) {
        *temp = (unsigned int)fieldValue.value.uiVal;
        return 0;  // Success via field values
    }
    
    // Fallback: Try GPU temperature as approximation
    unsigned int gpuTemp;
    result = nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, &gpuTemp);
    if (result == NVML_SUCCESS) {
        // For datacenter GPUs, HBM temp is usually close to GPU temp
        *temp = gpuTemp;
        return 1;  // Success with approximation
    }
    
    return -1;  // Failed
}

// Get hotspot/junction temperature via NVML (for newer GPUs)
int getHotspotTempViaNvml(nvmlDevice_t device, unsigned int* temp) {
    *temp = 0;
    
    // Try GPU temperature first (junction temp on newer drivers)
    nvmlReturn_t result = nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, temp);
    if (result == NVML_SUCCESS) {
        return 0;  // Success
    }
    
    return -1;  // Failed
}


// device struct
struct device
{
    uint32_t bar0;
    uint8_t bus, dev, func;
    uint32_t offset;
    uint16_t dev_id;
    const char *vram;
    const char *arch;
    const char *name;
    char pciBusId[NVML_DEVICE_PCI_BUS_ID_BUFFER_SIZE]; // Add this line
};


// variables
int fd;
void *map_base;
struct device devices[32];


// device table - GPUs that support direct register access for VRAM/Hotspot temps
struct device dev_table[] =
{
    // Ada Lovelace (AD10x)
    { .offset = 0x0000E2A8, .dev_id = 0x26B1, .vram = "GDDR6",  .arch = "AD102", .name =  "RTX A6000" },
    { .offset = 0x0000E2A8, .dev_id = 0x2684, .vram = "GDDR6X", .arch = "AD102", .name =  "RTX 4090" },
    { .offset = 0x0000E2A8, .dev_id = 0x2704, .vram = "GDDR6X", .arch = "AD103", .name =  "RTX 4080" },
    { .offset = 0x0000E2A8, .dev_id = 0x2782, .vram = "GDDR6X", .arch = "AD104", .name =  "RTX 4070 Ti" },
    { .offset = 0x0000E2A8, .dev_id = 0x2786, .vram = "GDDR6X", .arch = "AD104", .name =  "RTX 4070" },
    { .offset = 0x0000E2A8, .dev_id = 0x27b8, .vram = "GDDR6",  .arch = "AD104", .name =  "L4" },
    { .offset = 0x0000E2A8, .dev_id = 0x26b9, .vram = "GDDR6",  .arch = "AD102", .name =  "L40S" },
    { .offset = 0x0000E2A8, .dev_id = 0x26B5, .vram = "GDDR6",  .arch = "AD102", .name =  "L40" },
    
    // Ampere (GA10x)
    { .offset = 0x0000E2A8, .dev_id = 0x2230, .vram = "GDDR6",  .arch = "GA102", .name =  "RTX A6000" },
    { .offset = 0x0000E2A8, .dev_id = 0x2231, .vram = "GDDR6",  .arch = "GA102", .name =  "RTX A5000" },
    { .offset = 0x0000E2A8, .dev_id = 0x2232, .vram = "GDDR6",  .arch = "GA102", .name =  "RTX A4500" },
    { .offset = 0x0000E2A8, .dev_id = 0x2204, .vram = "GDDR6X", .arch = "GA102", .name =  "RTX 3090" },
    { .offset = 0x0000E2A8, .dev_id = 0x2208, .vram = "GDDR6X", .arch = "GA102", .name =  "RTX 3080 Ti" },
    { .offset = 0x0000E2A8, .dev_id = 0x2206, .vram = "GDDR6X", .arch = "GA102", .name =  "RTX 3080" },
    { .offset = 0x0000E2A8, .dev_id = 0x2216, .vram = "GDDR6X", .arch = "GA102", .name =  "RTX 3080 LHR" },
    { .offset = 0x0000EE50, .dev_id = 0x2484, .vram = "GDDR6",  .arch = "GA104", .name =  "RTX 3070" },
    { .offset = 0x0000EE50, .dev_id = 0x2488, .vram = "GDDR6",  .arch = "GA104", .name =  "RTX 3070 LHR" },
    { .offset = 0x0000E2A8, .dev_id = 0x2531, .vram = "GDDR6",  .arch = "GA106", .name =  "RTX A2000" },
    { .offset = 0x0000E2A8, .dev_id = 0x2571, .vram = "GDDR6",  .arch = "GA106", .name =  "RTX A2000" },
    
    // A100 - HBM2e (uses NVML for memory temp, not register access)
    { .offset = 0x00000000, .dev_id = 0x20B0, .vram = "HBM2e",  .arch = "GA100", .name =  "A100 PCIe" },
    { .offset = 0x00000000, .dev_id = 0x20B2, .vram = "HBM2e",  .arch = "GA100", .name =  "A100 SXM4" },
    { .offset = 0x00000000, .dev_id = 0x20F1, .vram = "HBM2e",  .arch = "GA100", .name =  "A100 PCIe 40GB" },
    { .offset = 0x00000000, .dev_id = 0x20B5, .vram = "HBM2e",  .arch = "GA100", .name =  "A100 80GB" },
    
    // H100 - HBM3
    { .offset = 0x00000000, .dev_id = 0x2330, .vram = "HBM3",   .arch = "GH100", .name =  "H100 PCIe" },
    { .offset = 0x00000000, .dev_id = 0x2331, .vram = "HBM3",   .arch = "GH100", .name =  "H100 SXM5" },
};

typedef struct {
    unsigned long long reasonBit;
    const char* reasonString;
} ThrottleReasonInfo;

// Define throttle reasons
const ThrottleReasonInfo throttleReasons[] = {
    {nvmlClocksThrottleReasonGpuIdle, "GpuIdle"},
    {nvmlClocksThrottleReasonApplicationsClocksSetting, "ApplicationsClocksSetting"},
    {nvmlClocksThrottleReasonSwPowerCap, "SwPowerCap"},
    {nvmlClocksThrottleReasonHwSlowdown, "HwSlowdown"},
    {nvmlClocksThrottleReasonSyncBoost, "SyncBoost"},
    {nvmlClocksThrottleReasonSwThermalSlowdown, "SwThermalSlowdown"},
    {nvmlClocksThrottleReasonHwThermalSlowdown, "HwThermalSlowdown"},
    {nvmlClocksThrottleReasonHwPowerBrakeSlowdown, "HwPowerBrakeSlowdown"},
    {nvmlClocksThrottleReasonDisplayClockSetting, "DisplayClockSetting"},
    // Add more throttle reasons as necessary
};


// Define human-readable names for throttle reasons
//static const char* throttle_reason_to_string(unsigned long long reason) {
//    switch (reason) {
//        case nvmlClocksThrottleReasonApplicationsClocksSetting: return "ApplicationsClocksSetting";
//        case nvmlClocksThrottleReasonDisplayClockSetting: return "DisplayClockSetting";
//        case nvmlClocksThrottleReasonGpuIdle: return "GpuIdle";
//        case nvmlClocksThrottleReasonHwPowerBrakeSlowdown: return "HwPowerBrakeSlowdown";
//        case nvmlClocksThrottleReasonHwSlowdown: return "HwSlowdown";
//        case nvmlClocksThrottleReasonHwThermalSlowdown: return "HwThermalSlowdown";
//        case nvmlClocksThrottleReasonNone: return "None";
//        case nvmlClocksThrottleReasonSwPowerCap: return "SwPowerCap";
//        case nvmlClocksThrottleReasonSwThermalSlowdown: return "SwThermalSlowdown";
//        case nvmlClocksThrottleReasonSyncBoost: return "SyncBoost";
//        default: return "Unknown";
//    }
//}

// prototypes
void cleanup(int signal);
void cleanup_sig_handler(void);
int pci_detect_dev(void);


// cleanup
void cleanup(int signal)
{
    if (signal == SIGHUP || signal == SIGINT || signal == SIGTERM)
    {
        if (map_base != (void *) -1)
            munmap(map_base, PG_SZ);
        if (fd != -1)
            close(fd);
        exit(0);
    }
}


// cleanup signal handler
void cleanup_sig_handler(void)
{
    struct sigaction sa;
    sa.sa_handler = &cleanup;
    sa.sa_flags = 0;
    sigfillset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0)
        perror("Cannot handle SIGINT");

    if (sigaction(SIGHUP, &sa, NULL) < 0)
        perror("Cannot handle SIGHUP");

    if (sigaction(SIGTERM, &sa, NULL) < 0)
        perror("Cannot handle SIGTERM");
}


// pci device detection
int pci_detect_dev(void)
{
    struct pci_access *pacc = NULL;
    struct pci_dev *pci_dev = NULL;
    int num_devs = 0;
    ssize_t dev_table_size = (sizeof(dev_table)/sizeof(struct device));

    pacc = pci_alloc();
    pci_init(pacc);
    pci_scan_bus(pacc);

for (pci_dev = pacc->devices; pci_dev; pci_dev = pci_dev->next)
{
    pci_fill_info(pci_dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);

    // Print out each NVIDIA device's ID for debugging
   if (debug_flag) {
	    if (pci_dev->vendor_id == 0x10DE) { // 0x10DE is NVIDIA's vendor ID
       		printf("Found NVIDIA Device - Vendor ID: %04x, Device ID: %04x\n", pci_dev->vendor_id, pci_dev->device_id);
    		}
	}

    for (uint32_t i = 0; i < dev_table_size; i++)
    {
        if (pci_dev->device_id == dev_table[i].dev_id)
        {
            devices[num_devs] = dev_table[i];
            devices[num_devs].bar0 = (pci_dev->base_addr[0] & 0xFFFFFFFF);
            devices[num_devs].bus = pci_dev->bus;
            devices[num_devs].dev = pci_dev->dev;
            devices[num_devs].func = pci_dev->func;

            // Format and store the PCI Bus ID
            sprintf(devices[num_devs].pciBusId, "%04x:%02x:%02x.0", pci_dev->domain, pci_dev->bus, pci_dev->dev);

            num_devs++;
        }
    }
}


    pci_cleanup(pacc);
    return num_devs;
}


// DC Exporter version
#define DCXP_VERSION "2.6.1"

// One-shot mode: run once and exit (let run.sh handle the loop)
// This ensures GPU devices are not held open between collections
#define ONE_SHOT_MODE 1

// Compare function for sorting GPUs by PCIe bus address
int compare_pci_gpus(const void *a, const void *b) {
    const PciGpuInfo *gpu_a = (const PciGpuInfo *)a;
    const PciGpuInfo *gpu_b = (const PciGpuInfo *)b;
    // Sort by bus first, then by device
    if (gpu_a->bus != gpu_b->bus) {
        return gpu_a->bus - gpu_b->bus;
    }
    return gpu_a->dev - gpu_b->dev;
}

// Detect ALL NVIDIA GPUs on PCIe bus (even those in VM passthrough)
int pci_detect_all_nvidia_gpus(void) {
    struct pci_access *pacc = pci_alloc();
    struct pci_dev *pci_dev;
    num_pci_gpus = 0;
    
    pci_init(pacc);
    pci_scan_bus(pacc);
    
    for (pci_dev = pacc->devices; pci_dev; pci_dev = pci_dev->next) {
        pci_fill_info(pci_dev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS);
        
        // 0x10DE is NVIDIA's vendor ID, class 0x0300 is VGA (GPU)
        if (pci_dev->vendor_id == 0x10DE && 
            ((pci_dev->device_class >> 8) == 0x03)) {  // Display controller
            
            if (num_pci_gpus < MAX_DEVICES) {
                pci_gpus[num_pci_gpus].vendor_id = pci_dev->vendor_id;
                pci_gpus[num_pci_gpus].device_id = pci_dev->device_id;
                pci_gpus[num_pci_gpus].bus = pci_dev->bus;
                pci_gpus[num_pci_gpus].dev = pci_dev->dev;
                pci_gpus[num_pci_gpus].func = pci_dev->func;
                snprintf(pci_gpus[num_pci_gpus].pci_bus_id, 32, "%04x:%02x:%02x.%x",
                         pci_dev->domain, pci_dev->bus, pci_dev->dev, pci_dev->func);
                pci_gpus[num_pci_gpus].in_nvml = 0;  // Will be updated later
                num_pci_gpus++;
            }
        }
    }
    
    pci_cleanup(pacc);
    
    // Sort GPUs by PCIe bus address for consistent ordering
    // This ensures the same GPU index regardless of libpci iteration order
    qsort(pci_gpus, num_pci_gpus, sizeof(PciGpuInfo), compare_pci_gpus);
    
    if (debug_flag) {
        for (int i = 0; i < num_pci_gpus; i++) {
            printf("PCIe GPU %d: %s (device_id=%04x)\n", 
                   i, pci_gpus[i].pci_bus_id, pci_gpus[i].device_id);
        }
    }
    
    return num_pci_gpus;
}

// Write metrics for GPU in VM passthrough mode
void write_vm_passthrough_metrics(FILE *metrics_file, int gpu_idx, const char *hostname, 
                                   const char *pci_bus_id, uint16_t device_id) {
    // Common label format for VM passthrough GPUs
    #define VM_LABELS "gpu=\"%d\",UUID=\"VM-PASSTHROUGH\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"GPU-%04x-VM\",Hostname=\"%s\""
    #define VM_DCGM_LABELS "gpu=\"%d\",UUID=\"VM-PASSTHROUGH\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"GPU-%04x-VM\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"N/A\""
    #define VM_DCXP_LABELS "gpu=\"%d\",UUID=\"VM-PASSTHROUGH\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"GPU-%04x-VM\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"N/A\""
    
    // DCXP unique metrics (0 values for VM passthrough)
    fprintf(metrics_file, "DCXP_FI_DEV_VRAM_TEMP{" VM_DCXP_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCXP_FI_DEV_HOT_SPOT_TEMP{" VM_DCXP_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCXP_GPU_SUPPORTED{" VM_DCXP_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCXP_AER_TOTAL_ERRORS{" VM_DCXP_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCXP_ERROR_STATE{" VM_DCXP_LABELS "} %d\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname, GPU_STATE_VM_PASSTHROUGH);
    fprintf(metrics_file, "DCXP_GPU_STATE{" VM_DCXP_LABELS "} %d\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname, GPU_STATE_VM_PASSTHROUGH);
    
    // DCGM-compatible metrics (0 values so wk03 shows up in dashboards)
    fprintf(metrics_file, "DCGM_FI_DEV_GPU_TEMP{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_POWER_USAGE{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_FAN_SPEED{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_SM_CLOCK{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_MEM_CLOCK{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_GPU_UTIL{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_MEM_COPY_UTIL{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_FB_FREE{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    fprintf(metrics_file, "DCGM_FI_DEV_FB_USED{" VM_DCGM_LABELS "} 0\n",
            gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    
    // Throttle reasons (all 0 for VM passthrough)
    const char *throttle_reasons[] = {
        "GpuIdle", "ApplicationsClocksSetting", "SwPowerCap", "HwSlowdown",
        "SyncBoost", "SwThermalSlowdown", "HwThermalSlowdown", "HwPowerBrakeSlowdown",
        "DisplayClockSetting"
    };
    for (size_t i = 0; i < sizeof(throttle_reasons)/sizeof(throttle_reasons[0]); i++) {
        fprintf(metrics_file, "DCXP_FI_DEV_CLOCKS_THROTTLE_REASON{reason=\"%s\"," VM_DCXP_LABELS "} 0\n",
                throttle_reasons[i], gpu_idx, pci_bus_id, gpu_idx, device_id, hostname);
    }
    
    #undef VM_LABELS
    #undef VM_DCGM_LABELS
    #undef VM_DCXP_LABELS
}

// Check if a GPU supports direct register access for VRAM/Hotspot temps
// Returns pointer to device entry or NULL if not supported
struct device* find_supported_device(uint16_t dev_id) {
    ssize_t dev_table_size = (sizeof(dev_table)/sizeof(struct device));
    for (int i = 0; i < dev_table_size; i++) {
        if (dev_table[i].dev_id == dev_id) {
            return &dev_table[i];
        }
    }
    return NULL;
}

// Look up PCIe index from pci_bus_id string
// Returns PCIe array index or -1 if not found
int getPciIndexFromBusId(const char* pci_bus_id) {
    for (int i = 0; i < num_pci_gpus; i++) {
        if (strcmp(pci_gpus[i].pci_bus_id, pci_bus_id) == 0) {
            return i;
        }
    }
    return -1;  // Not found
}

// Get PCI Bus ID for a GPU
int getGpuPciBusId(unsigned int gpuIndex, char* pciBusId, size_t maxLen) {
    nvmlDevice_t device;
    nvmlPciInfo_t pci_info;
    nvmlReturn_t result;
    
    result = nvmlDeviceGetHandleByIndex(gpuIndex, &device);
    if (result != NVML_SUCCESS) return -1;
    
    result = nvmlDeviceGetPciInfo(device, &pci_info);
    if (result != NVML_SUCCESS) return -1;
    
    snprintf(pciBusId, maxLen, "%04x:%02x:%02x.0", 
             pci_info.domain, pci_info.bus, pci_info.device);
    return 0;
}

// Count AER errors from /var/log/syslog for a specific GPU
unsigned int getTotalAerErrorsForDevice(unsigned int gpuIndex) {
    char pciBusId[32];
    if (getGpuPciBusId(gpuIndex, pciBusId, sizeof(pciBusId)) != 0) {
        return 0;
    }

    FILE *logFile = fopen("/var/log/syslog", "r");
    if (!logFile) {
        // Try kern.log as fallback
        logFile = fopen("/var/log/kern.log", "r");
        if (!logFile) return 0;
    }

    char *line = NULL;
    size_t len = 0;
    unsigned int aerErrorCount = 0;

    while (getline(&line, &len, logFile) != -1) {
        if (strstr(line, "AER") && strstr(line, pciBusId)) {
            aerErrorCount++;
        }
    }

    free(line);
    fclose(logFile);
    return aerErrorCount;
}

// Check GPU error state (0=OK, 1=Warning, 2=Error)
unsigned int checkGpuErrorState(unsigned int gpuIndex) {
    nvmlDevice_t device;
    nvmlReturn_t result;

    result = nvmlDeviceGetHandleByIndex(gpuIndex, &device);
    if (result != NVML_SUCCESS) {
        return 2; // Error state - can't get handle
    }

    // Check GPU temperature (if we can't query, assume error)
    unsigned int temp;
    result = nvmlDeviceGetTemperature(device, NVML_TEMPERATURE_GPU, &temp);
    if (result != NVML_SUCCESS) {
        return 2; // Error state
    }

    // Check memory info
    nvmlMemory_t memory;
    result = nvmlDeviceGetMemoryInfo(device, &memory);
    if (result != NVML_SUCCESS) {
        return 1; // Warning state
    }

    // Check for ECC errors (datacenter GPUs)
    unsigned long long eccErrors = 0;
    result = nvmlDeviceGetTotalEccErrors(device, NVML_MEMORY_ERROR_TYPE_UNCORRECTED, 
                                          NVML_VOLATILE_ECC, &eccErrors);
    if (result == NVML_SUCCESS && eccErrors > 0) {
        return 1; // Warning - ECC errors detected
    }

    return 0; // OK
}

// Count APT upgradable packages
unsigned int countUpgradablePackages(void) {
    FILE *fp;
    unsigned int count = 0;
    char buffer[1024];

    // Try reading from cache file first (faster)
    fp = fopen("/var/log/package-count.txt", "r");
    if (fp != NULL) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            sscanf(buffer, "Upgradable packages: %u", &count);
        }
        fclose(fp);
        return count;
    }

    // Fallback: run apt list --upgradable
    fp = popen("apt list --upgradable 2>/dev/null | tail -n +2 | wc -l", "r");
    if (fp != NULL) {
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            count = (unsigned int)atoi(buffer);
        }
        pclose(fp);
    }
    return count;
}

int main(int argc, char **argv)
{
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            debug_flag = 1;
        }
    }

    (void) argc;
    (void) argv;

    // Get hostname for metric labels
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }

    printf("DC Exporter v%s starting (hostname=%s)\n", DCXP_VERSION, hostname);
    
    cleanup_sig_handler();
    
    // Try to open /dev/mem for direct register access (non-fatal if it fails)
    char *MEM = "\x2f\x64\x65\x76\x2f\x6d\x65\x6d";
    int mem_access_available = 0;
    
    if ((fd = open(MEM, O_RDWR | O_SYNC)) != -1) {
        mem_access_available = 1;
        printf("/dev/mem available for direct register access\n");
    } else {
        printf("Warning: Can't read /dev/mem - direct register access disabled\n");
        printf("  (Run as root with iomem=relaxed for VRAM/Hotspot temps on supported GPUs)\n");
    }


// Main collection loop - in ONE_SHOT_MODE, runs once and exits
#if ONE_SHOT_MODE
int run_once = 1;
while (run_once)
{
    run_once = 0;  // Will exit after this iteration
#else
while (1)
{
#endif
    nvmlReturn_t result;
    unsigned int nvml_device_count = 0;
    int nvml_available = 0;
    char driver_version[NVML_SYSTEM_DRIVER_VERSION_BUFFER_SIZE];
    strcpy(driver_version, "unknown");
    
    // Step 1: Detect ALL NVIDIA GPUs on PCIe bus (even those in VM passthrough)
    int total_pci_gpus = pci_detect_all_nvidia_gpus();
    
    // Step 2: Try to initialize NVML (may fail if all GPUs in VM)
    result = nvmlInit();
    if (NVML_SUCCESS == result) {
        nvml_available = 1;
        
        // Get driver version
        result = nvmlSystemGetDriverVersion(driver_version, sizeof(driver_version));
        if (NVML_SUCCESS != result) {
            strcpy(driver_version, "unknown");
        }
        
        // Get device count via NVML
        result = nvmlDeviceGetCount(&nvml_device_count);
        if (NVML_SUCCESS != result) {
            nvml_device_count = 0;
        }
    } else {
        if (debug_flag) {
            fprintf(stderr, "NVML init failed (GPUs may be in VM passthrough): %s\n", 
                    nvmlErrorString(result));
        }
    }
    
    // Step 3: Detect PCI devices for direct register access (only for host GPUs)
    int num_supported_devs = 0;
    if (nvml_available && nvml_device_count > 0) {
        num_supported_devs = pci_detect_dev();
    }
    
    if (debug_flag) {
        printf("PCIe GPUs: %d, NVML GPUs: %d, Direct-access GPUs: %d\n", 
               total_pci_gpus, nvml_device_count, num_supported_devs);
    }
    
    // Step 4: Mark which PCI GPUs are in NVML (not passed to VM)
    for (int i = 0; i < num_pci_gpus; i++) {
        pci_gpus[i].in_nvml = 0;
        
        for (unsigned int j = 0; j < nvml_device_count && nvml_available; j++) {
            nvmlDevice_t nvml_device;
            nvmlPciInfo_t pci_info;
            
            if (nvmlDeviceGetHandleByIndex(j, &nvml_device) == NVML_SUCCESS &&
                nvmlDeviceGetPciInfo(nvml_device, &pci_info) == NVML_SUCCESS) {
                char nvml_pci_id[32];
                snprintf(nvml_pci_id, 32, "%04x:%02x:%02x.0", 
                         pci_info.domain, pci_info.bus, pci_info.device);
                if (strcmp(pci_gpus[i].pci_bus_id, nvml_pci_id) == 0) {
                    pci_gpus[i].in_nvml = 1;
                    break;
                }
            }
        }
    }
    
    // Open the metrics file in write mode to overwrite the existing content
    FILE *metrics_file = fopen("./metrics.txt", "w");
    if (metrics_file == NULL) {
        perror("Error opening metrics file");
        sleep(5);
        continue;  // Don't exit, retry
    }

    // Write headers for all metrics
    // DCXP unique metrics (not in dcgm-exporter)
    fprintf(metrics_file, "# HELP DCXP_FI_DEV_VRAM_TEMP VRAM temperature (in C) from DC Exporter. 0 if not supported or in VM.\n");
    fprintf(metrics_file, "# TYPE DCXP_FI_DEV_VRAM_TEMP gauge\n");
    fprintf(metrics_file, "# HELP DCXP_FI_DEV_HOT_SPOT_TEMP Hot Spot temperature (in C) from DC Exporter. 0 if not supported or in VM.\n");
    fprintf(metrics_file, "# TYPE DCXP_FI_DEV_HOT_SPOT_TEMP gauge\n");
    fprintf(metrics_file, "# HELP DCXP_FI_DEV_CLOCKS_THROTTLE_REASON Individual throttle reason for GPU clocks from DC Exporter.\n");
    fprintf(metrics_file, "# TYPE DCXP_FI_DEV_CLOCKS_THROTTLE_REASON gauge\n");
    fprintf(metrics_file, "# HELP DCXP_GPU_SUPPORTED Whether this GPU supports direct register access (1=yes, 0=no).\n");
    fprintf(metrics_file, "# TYPE DCXP_GPU_SUPPORTED gauge\n");
    fprintf(metrics_file, "# HELP DCXP_AER_TOTAL_ERRORS Total PCIe AER errors for GPU from syslog.\n");
    fprintf(metrics_file, "# TYPE DCXP_AER_TOTAL_ERRORS counter\n");
    fprintf(metrics_file, "# HELP DCXP_ERROR_STATE GPU error state (0=OK, 1=Warning, 2=Error, 3=VM, 4=Unavailable).\n");
    fprintf(metrics_file, "# TYPE DCXP_ERROR_STATE gauge\n");
    fprintf(metrics_file, "# HELP DCXP_GPU_STATE GPU state (0=OK, 1=Warning, 2=Error, 3=VM_Passthrough, 4=Unavailable).\n");
    fprintf(metrics_file, "# TYPE DCXP_GPU_STATE gauge\n");
    fprintf(metrics_file, "# HELP DCXP_GPU_AVAILABLE Whether GPUs are available to host (0=all in VM, 1=available).\n");
    fprintf(metrics_file, "# TYPE DCXP_GPU_AVAILABLE gauge\n");
    fprintf(metrics_file, "# HELP DCXP_GPU_COUNT Number of GPUs (total on PCIe / available to host).\n");
    fprintf(metrics_file, "# TYPE DCXP_GPU_COUNT gauge\n");
    
    // Standard DCGM-compatible metrics (for when dcgm-exporter is disabled)
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_GPU_TEMP GPU temperature (in C).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_GPU_TEMP gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_POWER_USAGE GPU power usage (in W).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_POWER_USAGE gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_FAN_SPEED GPU fan speed (0-100).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_FAN_SPEED gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_SM_CLOCK SM clock frequency (in MHz).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_SM_CLOCK gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_MEM_CLOCK Memory clock frequency (in MHz).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_MEM_CLOCK gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_GPU_UTIL GPU utilization (0-100).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_GPU_UTIL gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_MEM_COPY_UTIL Memory copy utilization (0-100).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_MEM_COPY_UTIL gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_FB_FREE Framebuffer memory free (in MB).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_FB_FREE gauge\n");
    fprintf(metrics_file, "# HELP DCGM_FI_DEV_FB_USED Framebuffer memory used (in MB).\n");
    fprintf(metrics_file, "# TYPE DCGM_FI_DEV_FB_USED gauge\n");
    
    // GPU availability metrics
    fprintf(metrics_file, "DCXP_GPU_AVAILABLE{Hostname=\"%s\"} %d\n", hostname, nvml_device_count > 0 ? 1 : 0);
    fprintf(metrics_file, "DCXP_GPU_COUNT{type=\"pcie\",Hostname=\"%s\"} %d\n", hostname, total_pci_gpus);
    fprintf(metrics_file, "DCXP_GPU_COUNT{type=\"nvml\",Hostname=\"%s\"} %d\n", hostname, nvml_device_count);
    
    // System metrics
    fprintf(metrics_file, "# HELP APT_UPGRADABLE_PACKAGES Number of APT packages that can be upgraded.\n");
    fprintf(metrics_file, "# TYPE APT_UPGRADABLE_PACKAGES gauge\n");
    unsigned int upgradable_packages = countUpgradablePackages();
    fprintf(metrics_file, "APT_UPGRADABLE_PACKAGES{Hostname=\"%s\"} %u\n", hostname, upgradable_packages);

    // First: Output metrics for GPUs in VM passthrough (detected on PCIe but not in NVML)
    // Use PCIe array index as GPU index for consistent labeling
    for (int i = 0; i < num_pci_gpus; i++) {
        if (!pci_gpus[i].in_nvml) {
            // Use PCIe index 'i' as gpu index for consistency across host/VM metrics
            write_vm_passthrough_metrics(metrics_file, i, hostname, 
                                         pci_gpus[i].pci_bus_id, pci_gpus[i].device_id);
        }
    }

    // Then: Iterate over ALL GPUs available via NVML
    for (unsigned int i = 0; i < nvml_device_count && nvml_available; i++) {
        nvmlDevice_t nvml_device;
        char uuid[NVML_DEVICE_UUID_BUFFER_SIZE];
        char name[NVML_DEVICE_NAME_BUFFER_SIZE];
        nvmlPciInfo_t pci_info;
        
        result = nvmlDeviceGetHandleByIndex(i, &nvml_device);
        if (NVML_SUCCESS != result) {
            fprintf(stderr, "Failed to get handle for device %d: %s\n", i, nvmlErrorString(result));
            continue;
        }

        result = nvmlDeviceGetUUID(nvml_device, uuid, NVML_DEVICE_UUID_BUFFER_SIZE);
        if (NVML_SUCCESS != result) {
            strcpy(uuid, "unknown");
        }

        result = nvmlDeviceGetName(nvml_device, name, NVML_DEVICE_NAME_BUFFER_SIZE);
        if (NVML_SUCCESS != result) {
            strcpy(name, "Unknown GPU");
        }

        result = nvmlDeviceGetPciInfo(nvml_device, &pci_info);
        char pci_bus_id[32];
        if (NVML_SUCCESS == result) {
            snprintf(pci_bus_id, sizeof(pci_bus_id), "%04x:%02x:%02x.0", 
                     pci_info.domain, pci_info.bus, pci_info.device);
        } else {
            strcpy(pci_bus_id, "unknown");
        }

        // Look up PCIe index for consistent GPU numbering
        // This ensures GPU index matches across host and VM metrics
        int pci_idx = getPciIndexFromBusId(pci_bus_id);
        if (pci_idx < 0) {
            pci_idx = i;  // Fallback to NVML index if not found in PCIe list
        }

        // Detect GPU architecture type
        GpuArchType arch = detectGpuArchitecture(nvml_device, name);
        
        // Check if this GPU is in our supported device table (for direct register access)
        struct device *supported_dev = NULL;
        for (int j = 0; j < num_supported_devs; j++) {
            if (strcmp(devices[j].pciBusId, pci_bus_id) == 0) {
                supported_dev = &devices[j];
                break;
            }
        }

        uint32_t vram_temp = 0;
        uint32_t hotspot_temp = 0;
        int is_supported = 0;
        int temp_source = 0; // 0=none, 1=register, 2=nvml

        // Try different methods based on GPU architecture
        if (arch == GPU_ARCH_DATACENTER) {
            // Datacenter GPUs (A100, H100, etc.) - use NVML Field Values API
            unsigned int mem_temp = 0;
            unsigned int hot_temp = 0;
            
            int mem_result = getMemoryTempViaNvml(nvml_device, &mem_temp);
            int hot_result = getHotspotTempViaNvml(nvml_device, &hot_temp);
            
            if (mem_result >= 0) {
                vram_temp = mem_temp;
                is_supported = 1;
                temp_source = 2; // NVML
            }
            if (hot_result >= 0) {
                hotspot_temp = hot_temp;
            }
            
            if (debug_flag) {
                printf("  Datacenter GPU: Using NVML API (mem=%d, hot=%d)\n", mem_result, hot_result);
            }
        }
        else if (supported_dev != NULL && supported_dev->offset != 0 && mem_access_available) {
            // Consumer/Professional GPUs with GDDR6/GDDR6X - use direct register access
            is_supported = 1;
            temp_source = 1; // Register
            
            // VRAM Temperature
            uint32_t phys_addr = (supported_dev->bar0 + supported_dev->offset);
            uint32_t base_offset = phys_addr & ~(PG_SZ-1);
            void *vram_map = mmap(0, PG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, base_offset);
            
            if (vram_map != MAP_FAILED) {
                void *virt_addr = (uint8_t *)vram_map + (phys_addr - base_offset);
                uint32_t read_result = *((uint32_t *)virt_addr);
                vram_temp = ((read_result & 0x00000fff) / 0x20);
                munmap(vram_map, PG_SZ);
            }

            // Hotspot Temperature
            uint32_t hotSpotRegAddr = supported_dev->bar0 + HOTSPOT_REGISTER_OFFSET;
            uint32_t hotSpotBaseOffset = hotSpotRegAddr & ~(PG_SZ-1);
            void *hotSpotMapBase = mmap(0, PG_SZ, PROT_READ, MAP_SHARED, fd, hotSpotBaseOffset);
            
            if (hotSpotMapBase != MAP_FAILED) {
                uint32_t hotSpotRegValue = *((uint32_t *)((char *)hotSpotMapBase + (hotSpotRegAddr - hotSpotBaseOffset)));
                munmap(hotSpotMapBase, PG_SZ);
                uint32_t temp_raw = (hotSpotRegValue >> 8) & 0xff;
                if (temp_raw < 0x7f) {
                    hotspot_temp = temp_raw;
                }
            }
            
            if (debug_flag) {
                printf("  Consumer GPU: Using direct register access\n");
            }
        }
        else if (arch == GPU_ARCH_PROFESSIONAL) {
            // Professional GPUs - try NVML first, then register
            unsigned int mem_temp = 0;
            unsigned int hot_temp = 0;
            
            // Try NVML first
            if (getMemoryTempViaNvml(nvml_device, &mem_temp) >= 0) {
                vram_temp = mem_temp;
                is_supported = 1;
                temp_source = 2;
            }
            if (getHotspotTempViaNvml(nvml_device, &hot_temp) >= 0) {
                hotspot_temp = hot_temp;
            }
            
            // If NVML didn't work and we have register access, try that
            if (vram_temp == 0 && supported_dev != NULL && mem_access_available) {
                uint32_t phys_addr = (supported_dev->bar0 + supported_dev->offset);
                uint32_t base_offset = phys_addr & ~(PG_SZ-1);
                void *vram_map = mmap(0, PG_SZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, base_offset);
                
                if (vram_map != MAP_FAILED) {
                    void *virt_addr = (uint8_t *)vram_map + (phys_addr - base_offset);
                    uint32_t read_result = *((uint32_t *)virt_addr);
                    vram_temp = ((read_result & 0x00000fff) / 0x20);
                    munmap(vram_map, PG_SZ);
                    is_supported = 1;
                    temp_source = 1;
                }
            }
            
            if (debug_flag) {
                printf("  Professional GPU: source=%d\n", temp_source);
            }
        }

        // Output VRAM temp (0 if not supported)
        // Use pci_idx for consistent GPU numbering across host/VM
        fprintf(metrics_file, "DCXP_FI_DEV_VRAM_TEMP{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %u\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, vram_temp);

        // Output Hotspot temp (0 if not supported)
        fprintf(metrics_file, "DCXP_FI_DEV_HOT_SPOT_TEMP{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %u\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, hotspot_temp);

        // Output whether GPU is supported for direct access
        fprintf(metrics_file, "DCXP_GPU_SUPPORTED{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %d\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, is_supported ? 1 : 0);

        // AER errors from syslog (still uses NVML index 'i' for NVML API calls)
        unsigned int aer_errors = getTotalAerErrorsForDevice(i);
        fprintf(metrics_file, "DCXP_AER_TOTAL_ERRORS{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %u\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, aer_errors);

        // GPU error state (still uses NVML index 'i' for NVML API calls)
        unsigned int error_state = checkGpuErrorState(i);
        fprintf(metrics_file, "DCXP_ERROR_STATE{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %u\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, error_state);

        // GPU state metric (same as error_state but more explicit)
        fprintf(metrics_file, "DCXP_GPU_STATE{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %u\n", 
                pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, error_state);

        // Throttle reasons (works for all GPUs via NVML)
        unsigned long long clocksThrottleReasons;
        result = nvmlDeviceGetCurrentClocksThrottleReasons(nvml_device, &clocksThrottleReasons);
        if (NVML_SUCCESS == result) {
            for (size_t j = 0; j < sizeof(throttleReasons)/sizeof(throttleReasons[0]); j++) {
                int value = (clocksThrottleReasons & throttleReasons[j].reasonBit) ? 1 : 0;
                fprintf(metrics_file, "DCXP_FI_DEV_CLOCKS_THROTTLE_REASON{reason=\"%s\",gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCXP_FI_DRIVER_VERSION=\"%s\"} %d\n",
                        throttleReasons[j].reasonString, pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, value);
            }
        }

        // Standard DCGM-compatible metrics (so dc-exporter can replace dcgm-exporter when needed)
        // GPU temperature
        unsigned int gpu_temp = 0;
        result = nvmlDeviceGetTemperature(nvml_device, NVML_TEMPERATURE_GPU, &gpu_temp);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_GPU_TEMP{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, gpu_temp);
        }

        // Power usage (in milliwatts from NVML, converted to watts)
        unsigned int power_mw = 0;
        result = nvmlDeviceGetPowerUsage(nvml_device, &power_mw);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_POWER_USAGE{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %.3f\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, power_mw / 1000.0);
        }

        // Fan speed
        unsigned int fan_speed = 0;
        result = nvmlDeviceGetFanSpeed(nvml_device, &fan_speed);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_FAN_SPEED{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, fan_speed);
        }

        // SM clock
        unsigned int sm_clock = 0;
        result = nvmlDeviceGetClockInfo(nvml_device, NVML_CLOCK_SM, &sm_clock);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_SM_CLOCK{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, sm_clock);
        }

        // Memory clock
        unsigned int mem_clock = 0;
        result = nvmlDeviceGetClockInfo(nvml_device, NVML_CLOCK_MEM, &mem_clock);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_MEM_CLOCK{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, mem_clock);
        }

        // GPU and memory utilization
        nvmlUtilization_t utilization;
        result = nvmlDeviceGetUtilizationRates(nvml_device, &utilization);
        if (result == NVML_SUCCESS) {
            fprintf(metrics_file, "DCGM_FI_DEV_GPU_UTIL{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, utilization.gpu);
            fprintf(metrics_file, "DCGM_FI_DEV_MEM_COPY_UTIL{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %u\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, utilization.memory);
        }

        // Framebuffer memory (in bytes from NVML, convert to MB for DCGM compatibility)
        nvmlMemory_t memory_info;
        result = nvmlDeviceGetMemoryInfo(nvml_device, &memory_info);
        if (result == NVML_SUCCESS) {
            unsigned long long fb_free_mb = memory_info.free / (1024 * 1024);
            unsigned long long fb_used_mb = memory_info.used / (1024 * 1024);
            fprintf(metrics_file, "DCGM_FI_DEV_FB_FREE{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %llu\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, fb_free_mb);
            fprintf(metrics_file, "DCGM_FI_DEV_FB_USED{gpu=\"%d\",UUID=\"%s\",pci_bus_id=\"%s\",device=\"nvidia%d\",modelName=\"%s\",Hostname=\"%s\",DCGM_FI_DRIVER_VERSION=\"%s\"} %llu\n",
                    pci_idx, uuid, pci_bus_id, pci_idx, name, hostname, driver_version, fb_used_mb);
        }

        if (debug_flag) {
            const char* arch_str = (arch == GPU_ARCH_DATACENTER) ? "DC" : 
                                   (arch == GPU_ARCH_CONSUMER) ? "Consumer" :
                                   (arch == GPU_ARCH_PROFESSIONAL) ? "Pro" : "Unknown";
            const char* src_str = (temp_source == 2) ? "NVML" : (temp_source == 1) ? "Register" : "None";
            printf("GPU %d (pci_idx=%d): %s (%s) - Arch=%s, VRAM=%u°C, Hotspot=%u°C, Supported=%d, Src=%s\n", 
                   i, pci_idx, name, pci_bus_id, arch_str, vram_temp, hotspot_temp, is_supported, src_str);
        }
    }


    fflush(stdout);
    // Make sure to flush the stream to write to the file immediately
    fflush(metrics_file);
    fclose(metrics_file);

    // Shutdown NVML if it was initialized
    if (nvml_available) {
        nvmlShutdown();
    }
    
#if ONE_SHOT_MODE
    // One-shot mode: exit after writing metrics
    // run.sh will restart us in 10 seconds
    if (debug_flag) {
        printf("One-shot collection complete, exiting\n");
    }
#else
    // Continuous mode: sleep before next iteration
    if (nvml_device_count == 0 && total_pci_gpus > 0) {
        // GPUs are on PCIe but not in NVML - likely VM passthrough
        if (debug_flag) {
            printf("All %d GPU(s) appear to be in VM passthrough, checking again in %ds\n", 
                   total_pci_gpus, VM_RETRY_INTERVAL);
        }
        sleep(VM_RETRY_INTERVAL);
    } else {
        sleep(5);  // Normal polling interval
    }
#endif
}

// Cleanup - close /dev/mem
if (fd != -1) {
    close(fd);
    fd = -1;
}

return 0;

}