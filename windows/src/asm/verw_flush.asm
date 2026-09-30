; verw_flush.asm
; MASM x64 assembly for the VERW instruction.
;
; VERW (Verify a Segment for Writing) is re-purposed by Intel microcode updates
; (MD_CLEAR) to clear all microarchitectural buffers (store buffer, load buffer,
; line-fill buffer) on vulnerable CPUs, mitigating MDS attacks (CVE-2018-12126,
; CVE-2018-12127, CVE-2018-11091) and some L1TF variants.
;
; PerformVerwFlush():
;   - Issues MFENCE to serialize all prior memory ops.
;   - Writes selector 0x2B (Ring-3 data segment, writable) onto the stack.
;   - Executes VERW [rsp] to trigger microarchitectural buffer clearing.
;   - Called from ExecuteSecurityBoundaryFlush() at any IRQL.
;
; Windows x64 ABI: no parameters, no return value, clobbers nothing callee-saved.

.CODE

PUBLIC PerformVerwFlush

PerformVerwFlush PROC
    ; Reserve 8 bytes aligned (RSP is already 16-byte aligned at function entry
    ; because the CALL instruction pushed the return address, making RSP mod 16 = 8;
    ; we subtract 8 more to reach 16-byte alignment before storing data).
    sub     rsp, 8h

    ; Store the Ring-3 data segment selector (0x2B) in the newly allocated slot.
    ; 0x2B = GDT[5] | RPL=3 — a present, writable data-segment descriptor on
    ; all x64 Windows systems. VERW sets ZF=1 confirming it is writable.
    mov     WORD PTR [rsp], 02Bh

    ; MFENCE: serialize all outstanding loads/stores before the VERW so that
    ; sensitive data written prior to this call has actually been committed to
    ; the microarchitectural buffers that VERW will flush.
    mfence

    ; VERW mem16: hardware reads the selector from [rsp], looks up the GDT
    ; descriptor, and — on CPUs with MD_CLEAR microcode — clears all
    ; microarchitectural data buffers (store buffer, load buffer, fill buffer).
    verw    WORD PTR [rsp]

    ; Restore stack.
    add     rsp, 8h
    ret
PerformVerwFlush ENDP

END
