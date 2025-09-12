# Technical Report: TF-M BL1_2 Boot Stage on Corstone-1000 MPS3

## 1. Executive Summary & High-Level Role

The TF-M BL1_2 boot stage is the second part of the immutable bootloader in the Trusted Firmware-M secure boot process. Its primary role is to verify the authenticity and integrity of the BL2 bootloader image before handing over execution control. This ensures that only authorized and untampered code is executed in the subsequent boot stages, forming a critical link in the chain of trust.

The BL1_2 code is typically stored in a secure, immutable storage medium like One-Time Programmable (OTP) memory or a secure enclave within the flash memory. On the Corstone-1000 MPS3 platform, it is loaded from this secure storage into a dedicated SRAM region for execution.

## 2. Execution Flow Diagram

The following Mermaid flowchart illustrates the main execution path of BL1_2:

```mermaid
graph TD
    A[BL1_2 Entry Point] --> B{boot_platform_init};
    B --> C{boot_platform_post_init};
    C --> D{boot_platform_pre_load};
    D --> E{Attempt to boot image 0};
    E --> F{validate_image(0)};
    F --> G{Success?};
    G -- No --> H{Attempt to boot image 1};
    H --> I{validate_image(1)};
    I --> J{Success?};
    J -- No --> K{boot_initiate_recovery_mode};
    K --> E;
    G -- Yes --> L{boot_platform_post_load};
    J -- Yes --> L;
    L --> M{collect_boot_measurement};
    M --> N{boot_platform_quit};
    N --> O[Jump to BL2];

    subgraph validate_image
        P[copy_and_decrypt_image] --> Q[validate_image_at_addr];
    end

    subgraph validate_image_at_addr
        R[is_image_signature_valid] --> S[is_image_security_counter_valid];
        S --> T[tfm_plat_set_nv_counter];
    end

    subgraph is_image_signature_valid
        U[bl1_sha256_compute] --> V{TFM_BL1_PQ_CRYPTO?};
        V -- Yes --> W[pq_crypto_verify];
        V -- No --> X[image_hash_check];
    end
```

## 3. Detailed Code Trace and Key Function Analysis

The main logic of BL1_2 is contained in `trusted-firmware-m/2.1.1/git/tfm/bl1/bl1_2/main.c`, with platform-specific implementations in `trusted-firmware-m/2.1.1/git/tfm/platform/ext/target/arm/corstone1000/bl1/boot_hal_bl1_2.c`.

### Chain of Trust Verification

The `is_image_signature_valid` function is the cornerstone of the chain of trust verification.

*   **LMS Signature Verification (`TFM_BL1_PQ_CRYPTO` enabled):**
    *   **Function:** `pq_crypto_verify`
    *   **Purpose:** To verify the LMS (Leighton-Micali Signature) of the BL2 image.
    *   **Implementation:** This function orchestrates the verification process by calling the underlying cryptographic hardware. On the Corstone-1000, this is the CC312 crypto accelerator. The public key used for verification is retrieved from OTP using the `tfm_plat_otp_read` function with the `PLAT_OTP_ID_BL1_ROTPK_0` identifier.

*   **Hash-based Verification (`TFM_BL1_PQ_CRYPTO` disabled):**
    *   **Function:** `image_hash_check`
    *   **Purpose:** To verify the SHA256 hash of the BL2 image.
    *   **Implementation:** This function reads the pre-provisioned hash of the BL2 image from OTP using `tfm_plat_otp_read` with the `PLAT_OTP_ID_BL2_IMAGE_HASH` identifier. It then compares this stored hash with the one computed from the loaded BL2 image.

### Non-Security Functions (Hardware Initialization)

*   **`boot_platform_init()`**: This function, located in `boot_hal_bl1_2.c`, performs the initial hardware setup. On the Corstone-1000 MPS3, its primary role is to initialize the stdio for logging purposes.

*   **`boot_platform_post_init()`**: Also in `boot_hal_bl1_2.c`, this function is called after the basic platform initialization. Its main responsibility is to initialize the flash memory driver using `FLASH_DEV_NAME.Initialize(NULL)`, making the BL2 image accessible for reading.

### Execution Handoff

*   **`boot_platform_quit()`**: This function, found in `boot_hal_bl1_2.c`, is responsible for the final handoff to BL2. It performs the following steps:
    1.  Uninitializes the CC3XX crypto accelerator and the flash driver.
    2.  Resets the watchdog timer to prevent a system reset.
    3.  Sets the Main Stack Pointer (MSP) to the entry point of the BL2 image's vector table.
    4.  Executes a final branch to the BL2 reset handler using the `boot_jump_to_next_image` function.

## 4. Key Data Structures and Security Mechanisms

### Key Data Structures

*   **`struct bl1_2_image_t`**: Defined in `trusted-firmware-m/2.1.1/git/tfm/bl1/bl1_2/lib/interface/image.h`, this structure encapsulates the BL2 image. It includes the encrypted image data, the signature, the IV, the image version, and the security counter.

### Security Hardening

*   **Anti-Rollback Protection:** BL1_2 implements anti-rollback protection using a security counter.
    *   The `is_image_security_counter_valid` function compares the security counter of the BL2 image with the value stored in a non-volatile counter in OTP (read via `tfm_plat_read_nv_counter`).
    *   The bootloader will only proceed if the image's counter is greater than or equal to the stored value.
    *   Upon successful validation, the OTP counter is updated with the new value using `tfm_plat_set_nv_counter`.

*   **Fault Injection (FI) Countermeasures:** The codebase extensively uses the Fault Injection Hardening (FIH) library (`fih.h`). Critical operations and comparisons are wrapped in `FIH_CALL` and other FIH macros to ensure resilience against fault injection attacks. In case of a critical failure, the system enters a `FIH_PANIC` state to prevent further execution of potentially compromised code.

## 5. Platform Integration and Tooling

### HAL (Hardware Abstraction Layer)

Porting BL1_2 to a new platform requires implementing a set of HAL functions, primarily defined in:

*   `boot_hal.h`: Functions for platform initialization, cleanup, and boot stage transition.
*   `tfm_plat_otp.h`: Functions for reading from and writing to OTP memory.
*   `tfm_plat_nv_counters.h`: Functions for managing non-volatile counters for anti-rollback protection.
*   `crypto.h`: Cryptographic functions, including hashing, decryption, and signature verification, which are typically offloaded to a hardware accelerator like the CC312.

### Associated Tooling

*   **`create_bl2_img.py`**: This script, located in `trusted-firmware-m/2.1.1/git/tfm/bl1/bl1_2/scripts/`, is essential for the secure boot process. It is used to sign the BL2 image with the appropriate key and package it into the `bl1_2_image_t` format that the BL1_2 bootloader expects.

