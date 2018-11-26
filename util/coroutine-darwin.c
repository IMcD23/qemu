/*
 * Win32 coroutine initialization code
 *
 * Copyright (c) 2011 Kevin Wolf <kwolf@redhat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/coroutine_int.h"






#include <stddef.h> /* size_t */
#include <stdint.h> /* uint32_t, uint64_t */

/** Context handle type. */
typedef struct CoroutineDarwin* sc_context_t;


/** Create a context with the given stack and procedure.
 **
 ** * `stack_ptr`:  Pointer to the buffer the context should use as stack.
 **                 Must be a valid pointer (not NULL).
 ** * `stack_size`: Size of the stack buffer provided in `stack_ptr`.
 ** * `proc`:       Procedure to invoke inside the new context. The
 **                 parameter passed to the proc will be the first value
 **                 yielded to the context through `sc_yield`.
 **
 ** **Note:** If the proc is allowed to run to its end, it will cause the
 **           process to exit.
 **
 ** **Important:** The stack must be big enough to be able to contain the
 **                maximum stack size used by the procedure. As this is
 **                implementation specific, it is up to the caller (or
 **                possibly attached debuggers) to ensure this is true. */
sc_context_t sc_context_create (
    void* stack_ptr,
    size_t stack_size
);

/** Destroy a context created through `sc_context_create`.
 **
 ** * `context`: Context to destroy. Must not be the currently executing
 **              context, or the main context (retrieved by calling
 **                `sc_main_context`). */
void sc_context_destroy (sc_context_t context);

/** Switch execution to another context, returning control to it, and
 ** passing the given value to it. Returns the value passed to
 ** `sc_switch` or `sc_yield` when control is returned to this context.
 **
 ** * `target`: Context to switch control to. Must be a valid context
 **             created by `sc_context_create`, or returned by
 **             `sc_main_context`.
 ** * `value`: Value to pass to the target context. */
void* sc_switch (sc_context_t target, void* value);


/** Get the handle for the currently executing context. */
sc_context_t sc_current_context (void);

/** Get the handle for this thread's main context. */
sc_context_t sc_main_context (void);


// PRIVATE


//
// Context Switching
//

typedef void* sc_context_sp_t;

typedef struct {
    sc_context_sp_t ctx;
    void* data;
} sc_transfer_t;

sc_transfer_t sc_jump_context (sc_context_sp_t to, void* vp);
sc_context_sp_t sc_make_context (void* sp, size_t size, void(*fn)(sc_transfer_t));

/* For the provided fcontext implementations, there's no necessary work to
 be done for freeing a context, but some custom backends (for proprietary
 hardware) do. */

static inline void sc_free_context (sc_context_sp_t ctx) { (void)ctx; }

//
// sc_context
//

typedef struct CoroutineDarwin
{
    Coroutine base;

    sc_context_sp_t ctx;
} CoroutineDarwin;

//
// Thread-locals
//

#define NO_INLINE    __attribute__((noinline))

NO_INLINE CoroutineDarwin* sc_get_main_context_data (void);
NO_INLINE CoroutineDarwin* sc_get_curr_context_data (void);
NO_INLINE void sc_set_curr_context_data (CoroutineDarwin* data);















#include <assert.h>     /* assert */
#include <stdint.h>     /* uintptr_t */

static __thread CoroutineDarwin t_main;
static __thread CoroutineDarwin* t_current;

/*
 * Compatibility
 */

#define ALIGNOF(x)   __alignof__(x)

/*
 * Private implementation
 */

static uintptr_t align_down (uintptr_t addr, uintptr_t alignment) {
    assert(alignment > 0);
    assert((alignment & (alignment - 1)) == 0);
    return addr & ~(alignment - 1);
}

static void context_proc (sc_transfer_t transfer) {
    CoroutineDarwin* data = (CoroutineDarwin*)transfer.data;
    assert(data != NULL);

    /* Jump back to parent */
    transfer = sc_jump_context(transfer.ctx, NULL);

    /* Update the current context */
    sc_current_context()->ctx = transfer.ctx;
    sc_set_curr_context_data(data);
    data->ctx = NULL;

    /* Execute the context proc */
    data->base.entry(transfer.data);
    qemu_coroutine_switch(&data->base, data->base.caller, COROUTINE_TERMINATE);
}

/*
 * Public implementation
 */

sc_context_t sc_context_create (
    void* stack_ptr,
    size_t stack_size
) {
    uintptr_t stack_addr;
    uintptr_t sp_addr;
    uintptr_t data_addr;
    sc_context_sp_t ctx;
    CoroutineDarwin* data;

    assert(stack_ptr != NULL);

    /* Determine the bottom of the stack */
    stack_addr = (uintptr_t)stack_ptr;
    sp_addr = stack_addr + stack_size;

    /* Reserve some space at the bottom for the context data */
    data_addr = sp_addr - sizeof(CoroutineDarwin);
    data_addr = align_down(data_addr, ALIGNOF(CoroutineDarwin));
    assert(data_addr > stack_addr);
    sp_addr = data_addr;

    /* Align the stack pointer to a 64-byte boundary */
    sp_addr = align_down(sp_addr, 64);
    assert(sp_addr > stack_addr);

    /* Determine the new stack size */
    stack_size = sp_addr - stack_addr;

    /* Create the context */
    ctx = sc_make_context((void*)sp_addr, stack_size, context_proc);
    assert(ctx != NULL);

    /* Create the context data at the reserved address */
    data = (CoroutineDarwin*)data_addr;

    /* Transfer the proc pointer to the context by briefly switching to it */
    data->ctx = sc_jump_context(ctx, data).ctx;
    return data;
}

void sc_context_destroy (sc_context_t context) {
    assert(context != sc_current_context());
    assert(context != sc_main_context());

    sc_free_context(context->ctx);
}

void* sc_switch (sc_context_t target, void* value) {
    CoroutineDarwin* this_ctx = sc_current_context();
    sc_transfer_t transfer;

    assert(target != NULL);

    if (target != this_ctx) {
        transfer = sc_jump_context(target->ctx, value);
        sc_current_context()->ctx = transfer.ctx;
        sc_set_curr_context_data(this_ctx);
        this_ctx->ctx = NULL;
        value = transfer.data;
    }

    return value;
}

sc_context_t sc_current_context (void) {
    CoroutineDarwin* current = sc_get_curr_context_data();
    return current ? current : sc_get_main_context_data();
}

sc_context_t sc_main_context (void) {
    return sc_get_main_context_data();
}

NO_INLINE CoroutineDarwin* sc_get_main_context_data (void) {
    return &t_main;
}

NO_INLINE CoroutineDarwin* sc_get_curr_context_data (void) {
    return t_current;
}

NO_INLINE void sc_set_curr_context_data (CoroutineDarwin* data) {
    t_current = data;
}

__attribute__((naked)) sc_context_sp_t sc_make_context (void* sp, size_t size, void(*fn)(sc_transfer_t)) {
         //; shift address in x0 (allocated stack) to lower 16 byte boundary
    asm("and x0, x0, ~0xF");

         //; reserve space for context-data on context-stack
    asm("sub  x0, x0, #0x70");

         //; third arg of sc_make_context() == address of context-function
         //; store address as a PC to jump in
    asm("str  x2, [x0, #0x60]");

         //; compute abs address of label finish
         //; 0x0c = 3 instructions * size (4) before label 'finish'

         //; TODO: Numeric offset since llvm still does not support labels in ADR. Fix:
         //;       http://lists.cs.uiuc.edu/pipermail/llvm-commits/Week-of-Mon-20140407/212336.html
    asm("adr  x1, 0x0c");

         //; save address of finish as return-address for context-function
         //; will be entered after context-function returns (LR register)
    asm("str  x1, [x0, #0x58]");

    asm("ret  lr");// ; return pointer to context-data (x0)
}

__attribute__((naked)) sc_transfer_t sc_jump_context (sc_context_sp_t to, void* vp) {
    asm (
         //; prepare stack for GP + FPU
         "sub  sp, sp, #0x70\n"

         //; save x19-x30
         "stp  x19, x20, [sp, #0x00]\n"
         "stp  x21, x22, [sp, #0x10]\n"
         "stp  x23, x24, [sp, #0x20]\n"
         "stp  x25, x26, [sp, #0x30]\n"
         "stp  x27, x28, [sp, #0x40]\n"
         "stp  fp,  lr,  [sp, #0x50]\n"

         //; save LR as PC
         "str  lr, [sp, #0x60]\n"

         //; store RSP (pointing to context-data) in X0
         "mov  x4, sp\n"

         //; restore RSP (pointing to context-data) from X1
         "mov  sp, x0\n"

         //; load x19-x30
         "ldp  x19, x20, [sp, #0x00]\n"
         "ldp  x21, x22, [sp, #0x10]\n"
         "ldp  x23, x24, [sp, #0x20]\n"
         "ldp  x25, x26, [sp, #0x30]\n"
         "ldp  x27, x28, [sp, #0x40]\n"
         "ldp  fp,  lr,  [sp, #0x50]\n"

         //; return sc_transfer_t from jump
         //; pass sc_transfer_t as first arg in context function
         //; X0 == FCTX, X1 == DATA
         "mov x0, x4\n"

         //; load pc
         "ldr  x4, [sp, #0x60]\n"

         //; restore stack from GP + FPU
         "add  sp, sp, #0x70\n"

         "ret x4"
    );
}


















/* This function is marked noinline to prevent GCC from inlining it
 * into coroutine_trampoline(). If we allow it to do that then it
 * hoists the code to get the address of the TLS variable "current"
 * out of the while() loop. This is an invalid transformation because
 * the SwitchToFiber() call may be called when running thread A but
 * return in thread B, and so we might be in a different thread
 * context each time round the loop.
 */
CoroutineAction __attribute__((noinline))
qemu_coroutine_switch(Coroutine *from_, Coroutine *to_,
                      CoroutineAction action)
{
    CoroutineDarwin *from = DO_UPCAST(CoroutineDarwin, base, from_);
    CoroutineDarwin *to = DO_UPCAST(CoroutineDarwin, base, to_);

    return sc_switch(to, to->base.entry_arg);

    // return COROUTINE_YIELD;
}

Coroutine *qemu_coroutine_new(void)
{
    size_t stack_size = COROUTINE_STACK_SIZE;
    void *stack = qemu_alloc_stack(&stack_size);
    CoroutineDarwin *co = sc_context_create(stack, stack_size);

    return &co->base;
}

void qemu_coroutine_delete(Coroutine *co_)
{
    CoroutineDarwin *co = DO_UPCAST(CoroutineDarwin, base, co_);

    sc_context_destroy(co);
    g_free(co);
}

Coroutine *qemu_coroutine_self(void)
{
    CoroutineDarwin *co = sc_current_context();

    return &co->base;
}

bool qemu_in_coroutine(void)
{
    CoroutineDarwin *co = sc_current_context();

    return co && co->base.caller;
}
