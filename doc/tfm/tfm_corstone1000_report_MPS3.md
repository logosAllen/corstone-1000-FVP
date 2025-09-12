# Trusted Firmware-M (TF-M) Runtime Analysis for Arm Corstone-1000 MPS3

## 1. Executive Summary & High-Level Role

### Primary Role of the TF-M Runtime

The TF-M Runtime, also known as the Secure Processing Environment (SPE), serves as the foundation of security on a PSA-compliant system. Its primary role is to create a trusted execution environment where sensitive operations can be performed and confidential data can be stored, isolated from the less-trusted Non-Secure Processing Environment (NSPE).

It functions as the core of the SPE by providing the following key services:

*   **Secure Boot**: It receives control from a trusted bootloader (BL2) and continues the chain of trust by verifying and loading all Secure Partitions.
*   **Isolation**: It configures and manages hardware isolation mechanisms (SAU and MPU on Corstone-1000) to enforce strict boundaries between the SPE and NSPE, and between individual Secure Partitions.
*   **Secure Services**: It hosts a set of secure services (e.g., Cryptography, Secure Storage, Attestation) in isolated compartments called Secure Partitions.
*   **Inter-Process Communication (IPC)**: It provides a secure IPC mechanism, based on the PSA Framework for M (FF-M) specification, that allows the NSPE and other Secure Partitions to request services from a Secure Partition without compromising system security.
*   **Scheduling**: It includes a secure scheduler that manages the execution of Secure Partitions.

### Memory Location and Execution Handoff

The TF-M Runtime code is located in the secure memory region of the device, as defined by the system's memory map and enforced by the Secure Attribute Unit (SAU). For the Corstone-1000, this is typically secure on-chip SRAM.

Execution begins when the second-stage bootloader (BL2) completes its tasks (verifying the integrity and authenticity of the TF-M image). BL2 then performs a jump to the entry point of the TF-M runtime image, passing control to the SPE. The entry point for the TF-M runtime is the `Reset_Handler` in the startup file, which eventually calls the C `main()` function located in `secure_fw/spm/core/main.c`.

## 2. Execution Flow Diagram

This flowchart illustrates the initialization flow of the TF-M Runtime on the Corstone-1000 platform.

```mermaid
graph TD
    A[BL2 Handoff] --> B(Reset_Handler);
    B --> C{main() in main.c};
    C --> D[tfm_core_init()];
    D --> E[tfm_hal_set_up_static_boundaries()];
    E --> F(Configure SAU/MPU for static isolation);
    D --> G[tfm_hal_platform_init()];
    G --> H(Initialize platform hardware: UART, Watchdog);
    D --> I(Provisioning);
    I --> J(Validate Boot Data);
    C --> K[BACKEND_SPM_INIT() SVC #0];
    K --> L{SVC_Handler};
    L --> M{spm_svc_handler()};
    M --> N{handle_spm_svc_requests()};
    N --> O{tfm_spm_init()};
    subgraph SPM Initialization
        O --> P{Partition Loading Loop};
        P --> Q(load_a_partition_assuredly);
        Q --> R(load_services_assuredly);
        R --> S(tfm_hal_bind_boundary);
        S --> T(backend_init_comp_assuredly);
        T --> P;
    end
    P --> U{backend_system_run()};
    U --> V(Start Secure Scheduler);
    V --> W(Execute first Secure Partition);
    W --> X(NS Agent eventually runs);
    X --> Y(Jump to NSPE Entry Point);

```

## 3. Detailed Code Trace and Key Function Analysis

### SPM Initialization (`tfm_spm_init`)

The `tfm_spm_init` function, located in `secure_fw/spm/core/spm_ipc.c`, is the heart of the runtime initialization. It is responsible for discovering, loading, and initializing all the Secure Partitions that comprise the SPE.

The core of this function is a `while` loop that orchestrates the loading process:

```c
// In trusted-firmware-m/2.1.1/git/tfm/secure_fw/spm/core/spm_ipc.c

uint32_t tfm_spm_init(void)
{
    // ... initialization of connection pools and lists ...

    while (1) {
        partition = load_a_partition_assuredly(PARTITION_LIST_ADDR);
        if (partition == NO_MORE_PARTITION) {
            break;
        }

        service_setting = load_services_assuredly(...);

        load_irqs_assuredly(partition);

        FIH_CALL(tfm_hal_bind_boundary, fih_rc, partition->p_ldinf,
                 &partition->boundary);
        // ...

        backend_init_comp_assuredly(partition, service_setting);
    }

    return backend_system_run();
}
```

*   **`load_a_partition_assuredly()`**: This function is responsible for finding and parsing the manifest for the next Secure Partition. The build system, using the `tfm_parse_manifest_list.py` script, auto-generates C files containing `partition_load_info_t` structures for each partition. This function iterates through this auto-generated data, populating a runtime `struct partition_t` for each partition it finds.
*   **`load_services_assuredly()`**: For each partition, this function loads the services it offers, creating `struct service_t` entries.
*   **`backend_init_comp_assuredly()`**: This function sets up the execution context for the partition, including its thread, stack, and entry point.

### Hardware Isolation Setup

On the Corstone-1000 MPS3, hardware isolation is enforced by the SAU and MPU.

*   **SAU (Secure Attribute Unit)**: The SAU is configured by the bootloader (BL2) *before* the TF-M runtime starts. It creates the high-level memory map, defining which regions of memory are Secure and which are Non-Secure. The TF-M runtime executes entirely within the Secure region defined by the SAU.

*   **MPU (Memory Protection Unit)**: The MPU is configured by the TF-M runtime itself to create finer-grained isolation boundaries *within* the Secure region. This is done in the `tfm_hal_set_up_static_boundaries` function in `platform/ext/target/arm/corstone1000/tfm_hal_isolation.c`.

    ```c
    // In trusted-firmware-m/2.1.1/git/tfm/platform/ext/target/arm/corstone1000/tfm_hal_isolation.c
    enum tfm_hal_status_t tfm_hal_set_up_static_boundaries(
                                                uintptr_t *p_spm_boundary)
    {
    #ifdef CONFIG_TFM_ENABLE_MEMORY_PROTECT
        // ...
        ARM_MPU_Disable();

        // Configure a background region for the whole SRAM
        base = SRAM_BASE;
        limit = SRAM_BASE + SRAM_SIZE;
        ret = configure_mpu(rnr++, base, limit, XN_EXEC_OK, AP_RO_PRIV_UNPRIV);
        // ...

        // Configure regions for secure data (privileged RW)
        base = S_DATA_START;
        limit = S_DATA_START + RAM_MPU_REGION_BLOCK_1_SIZE;
        ret = configure_mpu(rnr++, base, limit, XN_EXEC_NOT_OK, AP_RW_PRIV_ONLY);
        // ...

        // Configure regions for application data/stack (unprivileged RW)
        base = (uint32_t)&REGION_NAME(Image$$, TFM_APP_RW_STACK_START, $$Base);
        limit = (uint32_t)&REGION_NAME(Image$$, TFM_APP_RW_STACK_END, $$Base);
        // ...

        arm_mpu_enable();
    #endif
        // ...
    }
    ```
    This function sets up a static MPU map at boot time. This map defines regions for code and data, and assigns access permissions (e.g., privileged vs. unprivileged, read-only vs. read-write). This static configuration corresponds to **TF-M Isolation Level 2**.

### Secure Service Call Handling (`psa_call`)

A `psa_call` originating from the NSPE follows this path:

1.  **Veneer**: The NSPE application calls the `psa_call` function. This is a veneer function that executes an `SVC` (Supervisor Call) instruction, trapping into the SPE. The specific veneer is `tfm_psa_call_pack_svc` in `secure_fw/spm/core/psa_interface_svc.c`, which executes `SVC #TFM_SVC_PSA_CALL`.

2.  **`SVC_Handler`**: The `SVC` instruction is caught by the `SVC_Handler` in `secure_fw/spm/core/arch/tfm_arch_v8m_main.c`. This handler saves the caller's context and calls the C function `spm_svc_handler`.

3.  **`spm_svc_handler`**: This function in `tfm_svcalls.c` is the central SVC dispatcher. It determines that the call is a PSA API call (`TFM_SVC_IS_PSA_API` is true) and dispatches it to `prepare_to_thread_mode_spm`.

4.  **`prepare_to_thread_mode_spm`**: This function looks up the target function in the `psa_api_svc_func_table`. For `TFM_SVC_PSA_CALL`, this is `tfm_spm_client_psa_call`.

5.  **`tfm_spm_client_psa_call`**: This function in `psa_call_api.c` is the core of the `psa_call` logic. It validates the service handle, checks the caller's authorization, and populates a `psa_msg_t` structure with the call's parameters.

6.  **`backend_messaging`**: Finally, `tfm_spm_client_psa_call` calls `backend_messaging` (in `backend_ipc.c`). This function adds the message to the target partition's message queue and asserts the partition's message signal. The SPM's scheduler will then schedule the target partition to run, which will then retrieve and process the message.

### NSPE Handoff

The handoff to the NSPE is managed by the SPM's scheduler and the **Non-Secure Agent** partition.

1.  At the end of `tfm_spm_init`, `backend_system_run` is called.
2.  `backend_system_run` starts the secure scheduler via `thrd_start_scheduler()`.
3.  The scheduler will eventually run the Non-Secure Agent partition.
4.  The entry function for the NS Agent is responsible for performing the final software jump to the NSPE entry point. This entry point address is retrieved from the HAL via `tfm_hal_get_ns_entry_point()`.

## 4. Key Data Structures and Security Mechanisms

### Data Structures

*   **`struct partition_load_info_t`**: Defined in `load/partition_defs.h`, this structure holds the static data for a partition, loaded from its manifest at build time.
    ```c
    struct partition_load_info_t {
        uint32_t        psa_ff_ver;
        int32_t         pid;
        uint32_t        flags;
        uintptr_t       entry;
        size_t          stack_size;
        // ... and more
    };
    ```
*   **`struct partition_t`**: Defined in `core/spm.h`, this is the runtime representation of a partition.
    ```c
    struct partition_t {
        const struct partition_load_info_t *p_ldinf;
        uintptr_t                          boundary;
        uint32_t                           signals_allowed;
        // ... and more
        struct thread_t                    thrd;
    };
    ```
*   **`struct connection_t`**: Defined in `core/spm.h`, this represents an active connection to a service.
    ```c
    struct connection_t {
        uint32_t status;
        struct partition_t *p_client;
        const struct service_t *service;
        psa_msg_t msg;
        // ... and more
    };
    ```

### Security Hardening (Isolation Levels)

The Corstone-1000 implementation, as analyzed, enforces **TF-M Isolation Level 2**:

*   **Level 1 (SPM vs. Partitions)**: The SPM runs at a privileged level, while Secure Partitions run at an unprivileged level. This is enforced by the `nPRIV` bit in the `CONTROL` register, which is set by `tfm_hal_activate_boundary` during a context switch.
*   **Level 2 (Inter-Partition)**: A static MPU configuration is used to protect Secure Partitions from each other to some extent. Unprivileged partitions cannot access the data of the SPM or other partitions if it's outside their allowed memory regions (defined by the MPU at boot).
*   **Level 3 (Full Isolation)**: This level is **not** implemented in the analyzed code. Level 3 would require the MPU to be dynamically reconfigured on every context switch to grant a partition access *only* to its own memory, providing much stricter isolation. The `tfm_hal_activate_boundary` function would need to be much more complex to support this.

## 5. Platform Integration and Tooling

### HAL (Hardware Abstraction Layer)

The SPM relies on a set of HAL functions for platform-specific operations. For the Corstone-1000, the most critical runtime HAL functions are:

*   **`tfm_hal_platform_init()`**: Initializes platform peripherals like the UART and watchdog.
*   **`tfm_hal_set_up_static_boundaries()`**: Configures the MPU with a static memory map at boot.
*   **`tfm_hal_bind_boundary()`**: Creates a handle representing a partition's required privilege level.
*   **`tfm_hal_activate_boundary()`**: Switches the CPU between privileged and unprivileged modes during a context switch.
*   **`tfm_hal_get_ns_entry_point()`**: Retrieves the entry point address for the Non-Secure application.

### Associated Tooling

The **`tools/tfm_parse_manifest_list.py`** script is a critical part of the TF-M build system. It is a Python script that:

1.  **Parses Manifests**: Reads a list of YAML files that point to the individual Secure Partition manifests.
2.  **Validates**: Checks the manifests for compliance with the PSA FF-M specification.
3.  **Generates Code**: Uses Jinja2 templates to auto-generate C source and header files. These files contain the static data structures (`partition_load_info_t`, etc.) that the SPM uses at runtime to discover and load the partitions.

This script acts as the bridge between the high-level, human-readable partition manifests and the low-level data structures required by the SPM, greatly simplifying the configuration of the secure environment.
