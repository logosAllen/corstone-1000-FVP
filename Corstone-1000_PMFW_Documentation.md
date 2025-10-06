# Corstone-1000 FVP Power Management Firmware (PMFW) Documentation

## 1. Conclusion

Corstone-1000 FVP **does not have a separate, dedicated Power Management Firmware (PMFW)**. Its system-level power and platform control functions are implemented within two key pieces of Arm's trusted firmware: **Trusted Firmware-M (TF-M)** running on the Secure Enclave, and **Trusted Firmware-A (TF-A)** running on the main application processor.

The key findings are:

*   **Trusted Firmware-M (TF-M)**:
    *   Provides a **Platform Service** for secure, platform-specific operations.
    *   In the Corstone-1000 implementation, this service is used for functions like Firmware Update (FWU), but **does not expose any advanced power management APIs** (e.g., deep sleep, clock scaling) to the Non-secure world.

*   **Trusted Firmware-A (TF-A)**:
    *   Implements the **Power State Coordination Interface (PSCI)**, which is the standard way for a non-secure OS (like Linux) to request power management operations.
    *   The Corstone-1000 implementation of PSCI supports **system reset** and **secondary core power-on/off**.
    *   Crucially, the implementation **does not support deeper sleep states** (`cpu_suspend`) or system shutdown (`system_off`).

**In summary**, power management on the Corstone-1000 FVP is limited. The OS can use standard processor instructions like `WFI` (Wait For Interrupt) for shallow idle states, and it can use PSCI to reset the system or manage CPU cores, but it cannot request the platform to enter a deep sleep or power-off state via the trusted firmware.

---

## 2. Trusted Firmware-M (TF-M) Analysis

### 2.1. Firmware Architecture: TF-M Platform Service

TF-M uses a generic **Platform Service** to allow secure partitions and non-secure applications to interact with platform-specific hardware. This service acts as a secure entry point, routing requests to a platform-specific **Hardware Abstraction Layer (HAL)**.

The key entry point for these operations is the `tfm_platform_hal_ioctl` function, which dispatches requests based on an IOCTL code.

### 2.2. Control Flow and Source Code

For Corstone-1000, the Platform Service HAL is implemented in:
`platform/ext/target/arm/corstone1000/services/src/tfm_platform_system.c`

Analysis of this file shows that the `tfm_platform_hal_ioctl` function only handles requests related to Firmware Update (FWU) and the Firmware Management Protocol (FMP). There are no IOCTL requests related to power management.

```c
// platform/ext/target/arm/corstone1000/services/src/tfm_platform_system.c

enum tfm_platform_err_t tfm_platform_hal_ioctl(tfm_platform_ioctl_req_t request,
                                               psa_invec  *in_vec,
                                               psa_outvec *out_vec)
{
    /* ... (code omitted for brevity) ... */
    switch(request) {
        case IOCTL_CORSTONE1000_FWU_FLASH_IMAGES:
            /* ... */
            break;
        case IOCTL_CORSTONE1000_FWU_HOST_ACK:
            /* ... */
            break;
        case IOCTL_CORSTONE1000_FMP_GET_IMAGE_INFO:
            /* ... */
            break;
        default:
            ret = TFM_PLATFORM_ERR_NOT_SUPPORTED;
            break;
    }
    return ret;
}
```

---

## 3. Trusted Firmware-A (TF-A) Analysis

### 3.1. Firmware Architecture: Power State Coordination Interface (PSCI)

TF-A implements the PSCI, which provides a generic interface for the Non-secure world OS to request power operations from the secure firmware. The firmware then performs the required platform-specific actions. The platform's support for different power states is defined by which PSCI handler functions it implements and registers in the `plat_psci_ops` structure.

### 3.2. Control Flow and Source Code

For Corstone-1000, the PSCI implementation is located in:
`plat/arm/board/corstone1000/common/corstone1000_pm.c`

Analysis of this file reveals the extent of PSCI support:

*   **Supported Functions**:
    *   `system_reset`: Resets the system by triggering the secure watchdog.
    *   `pwr_domain_on`: Powers on secondary CPU cores.
    *   `pwr_domain_on_finish`: Initializes the GIC after a core is powered on.

*   **Unsupported Functions**:
    *   The implementation **does not** provide handlers for `cpu_suspend`, `system_off`, or `system_suspend`. This confirms the lack of support for deep sleep or power-off states initiated from the OS.

Here is the relevant code snippet from `corstone1000_pm.c` showing the registered PSCI operations:

```c
// plat/arm/board/corstone1000/common/corstone1000_pm.c

plat_psci_ops_t plat_arm_psci_pm_ops = {
#if defined(CORSTONE1000_FVP_MULTICORE)
	.pwr_domain_on = corstone1000_pwr_domain_on,
	.pwr_domain_on_finish = corstone1000_pwr_domain_on_finish,
	.validate_ns_entrypoint = corstone1000_validate_ns_entrypoint,
	.system_reset = corstone1000_system_reset,
#else
	.validate_ns_entrypoint = NULL,
	.system_reset = corstone1000_system_reset,
#endif
};

const plat_psci_ops_t *plat_arm_psci_override_pm_ops(plat_psci_ops_t *ops)
{
	ops = &plat_arm_psci_pm_ops;
	return ops;
}
```

---

## 4. Source Code and Build Environment

### 4.1. Source Code Repositories

*   **Trusted Firmware-M (TF-M)**: `https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git`
*   **Trusted Firmware-A (TF-A)**: `https://review.trustedfirmware.org/TF-A/trusted-firmware-a`

### 4.2. Yocto Build Environment

Both TF-M and TF-A are built as part of the Corstone-1000 firmware using the **Yocto Project**. The configurations are found in the `meta-arm` layer.

*   **TF-M Configuration**:
    *   Recipe: `recipes-bsp/trusted-firmware-m/trusted-firmware-m_%.bbappend`
    *   Corstone-1000 Specifics: `recipes-bsp/trusted-firmware-m/trusted-firmware-m-corstone1000.inc`

*   **TF-A Configuration**:
    *   Recipe: `recipes-bsp/trusted-firmware-a/trusted-firmware-a_%.bbappend`
    *   Corstone-1000 Specifics: `recipes-bsp/trusted-firmware-a/trusted-firmware-a-corstone1000.inc`