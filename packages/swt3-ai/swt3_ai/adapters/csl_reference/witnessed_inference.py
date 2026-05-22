"""CSL Reference: Witnessed Inference Kernel Launch.

Demonstrates the host-side pattern for launching a CSL inference kernel
with SWT3 witnessing. The witness tap sits between the host Python code
and the SdkRuntime, observing kernel launches and D2H transfers without
modifying the CSL kernel itself.

This is the "Token Stream Tap" pattern: the host observes I/O at the
fabric boundary, minting compliance anchors from the data that crosses
the host-device interface.

Reference only. Requires Cerebras SDK and WSE-3 hardware.

Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
"""

from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np


def run_witnessed_inference(
    runtime: Any,
    kernel_name: str,
    input_tensor: "np.ndarray",
    output_symbol: Any,
    output_shape: tuple,
    output_dtype: Any = None,
) -> "np.ndarray":
    """Reference implementation: launch a CSL kernel with SWT3 witnessing.

    This function shows the canonical host-side pattern:
    1. Copy input to device (H2D)
    2. Launch kernel
    3. Copy output from device (D2H)
    4. Witness tap fires automatically on D2H (if middleware is patched)

    Args:
        runtime: Cerebras SdkRuntime instance (patched with CerebrasWitnessMiddleware).
        kernel_name: CSL kernel function name to launch.
        input_tensor: Input data as numpy array.
        output_symbol: Device symbol for output buffer.
        output_shape: Shape of output tensor.
        output_dtype: Numpy dtype for output. Defaults to input dtype.

    Returns:
        Output tensor from device.

    Note:
        When runtime is patched with CerebrasWitnessMiddleware:
        - launch() records kernel name and start time
        - memcpy_d2h() hashes the output and mints an anchor
        - Zero latency added to the kernel execution itself
        - All witnessing happens on the host side, not the fabric
    """
    import numpy as np

    if output_dtype is None:
        output_dtype = input_tensor.dtype

    # H2D: copy input to device
    # In a real CSL program, the input symbol would be bound at compile time
    if hasattr(runtime, "memcpy_h2d"):
        runtime.memcpy_h2d(input_tensor)

    # Launch: kernel executes on WSE fabric
    # The patched launch() records timing + kernel name for the witness
    runtime.launch(kernel_name, nonblock=False)

    # D2H: copy output from device
    # The patched memcpy_d2h() hashes the result and mints an anchor
    result = runtime.memcpy_d2h(output_symbol, output_shape, output_dtype)

    return result


def run_witnessed_pipeline(
    runtime: Any,
    stages: list,
    input_tensor: "np.ndarray",
) -> "np.ndarray":
    """Reference implementation: multi-stage CSL pipeline with witnessing.

    Each kernel launch in the pipeline generates a separate witness anchor,
    creating a chain of custody across the inference pipeline.

    Args:
        runtime: Patched SdkRuntime.
        stages: List of dicts with keys:
            - kernel: CSL kernel name
            - output_symbol: device output symbol
            - output_shape: output tensor shape
        input_tensor: Initial input data.

    Returns:
        Final output tensor after all stages.
    """
    current = input_tensor

    for stage in stages:
        current = run_witnessed_inference(
            runtime=runtime,
            kernel_name=stage["kernel"],
            input_tensor=current,
            output_symbol=stage["output_symbol"],
            output_shape=stage["output_shape"],
        )

    return current
