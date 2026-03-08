# Code Lifting Examples

Concrete before/after examples demonstrating the lifting process. Each example shows the raw IDA decompiled output and the lifted result with explanations of changes made.

---

## Example 1: Constructor with unique_ptr Move Semantics

### Before (IDA output from `appinfo_dll_BinaryAndStrategy_group_1.cpp`)

```cpp
// Function Name: BinaryAndStrategy::BinaryAndStrategy
// Mangled Name: ??0BinaryAndStrategy@@AEAA@V?$unique_ptr@VRateLimiterStrategy@@U?$default_delete@VRateLimiterStrategy@@@wistd@@@wistd@@0@Z
// Function Signature (Extended): __int64 __fastcall BinaryAndStrategy::BinaryAndStrategy()
// Function Signature: private: BinaryAndStrategy::BinaryAndStrategy(class wistd::unique_ptr<class RateLimiterStrategy, struct wistd::default_delete<class RateLimiterStrategy>>, class wistd::unique_ptr<class RateLimiterStrategy, struct wistd::default_delete<class RateLimiterStrategy>>)
_QWORD *__fastcall BinaryAndStrategy::BinaryAndStrategy(_QWORD *a1, _QWORD *a2, _QWORD *a3)
{
  void (__fastcall ***v5)(_QWORD, __int64); // rax
  void (__fastcall ***v6)(_QWORD, __int64); // rax
  void (__fastcall ***v7)(_QWORD, __int64); // rcx
  void (__fastcall ***v8)(_QWORD, __int64); // rcx

  *a1 = &BinaryAndStrategy::'vftable';
  v5 = (void (__fastcall ***)(_QWORD, __int64))*a2;
  *a2 = 0;
  a1[1] = v5;
  v6 = (void (__fastcall ***)(_QWORD, __int64))*a3;
  *a3 = 0;
  a1[2] = v6;
  v7 = (void (__fastcall ***)(_QWORD, __int64))*a2;
  *a2 = 0;
  if ( v7 )
    (**v7)(v7, 1);
  v8 = (void (__fastcall ***)(_QWORD, __int64))*a3;
  *a3 = 0;
  if ( v8 )
    (**v8)(v8, 1);
  return a1;
}
```

### After (Lifted)

```cpp
// Reconstructed layout (from pointer access patterns)
struct BinaryAndStrategy {
    void *vtable;                           // +0x00: vftable pointer
    RateLimiterStrategy *primaryStrategy;   // +0x08: first rate limiter
    RateLimiterStrategy *secondaryStrategy; // +0x10: second rate limiter
};

/**
 * BinaryAndStrategy::BinaryAndStrategy - Constructor.
 *
 * Initializes a BinaryAndStrategy by taking ownership of two
 * RateLimiterStrategy unique_ptrs via move semantics. After moving
 * the strategy pointers into this object, the source unique_ptrs
 * are reset and their previous values (if any) are destroyed.
 *
 * @param this              Object being constructed
 * @param primaryOwner      unique_ptr holding the primary RateLimiterStrategy (moved from)
 * @param secondaryOwner    unique_ptr holding the secondary RateLimiterStrategy (moved from)
 * @return                  Pointer to the constructed object
 */
BinaryAndStrategy *BinaryAndStrategy::BinaryAndStrategy(
    BinaryAndStrategy *this,
    wistd::unique_ptr<RateLimiterStrategy> *primaryOwner,
    wistd::unique_ptr<RateLimiterStrategy> *secondaryOwner)
{
    // Initialize vtable
    this->vtable = &BinaryAndStrategy::vftable;

    // Move primary strategy: take ownership, null out source
    RateLimiterStrategy *primaryPtr = primaryOwner->get();
    primaryOwner->release();  // *primaryOwner = nullptr
    this->primaryStrategy = primaryPtr;

    // Move secondary strategy: take ownership, null out source
    RateLimiterStrategy *secondaryPtr = secondaryOwner->get();
    secondaryOwner->release();  // *secondaryOwner = nullptr
    this->secondaryStrategy = secondaryPtr;

    // Destroy any remaining object in primaryOwner (reset after move)
    RateLimiterStrategy *oldPrimary = primaryOwner->get();
    primaryOwner->release();
    if (oldPrimary) {
        oldPrimary->Release(1);  // invoke destructor via vtable
    }

    // Destroy any remaining object in secondaryOwner (reset after move)
    RateLimiterStrategy *oldSecondary = secondaryOwner->get();
    secondaryOwner->release();
    if (oldSecondary) {
        oldSecondary->Release(1);  // invoke destructor via vtable
    }

    return this;
}
```

### Changes Made
- `a1` -> `this` (first parameter of constructor)
- `a2` -> `primaryOwner` (from mangled name: first unique_ptr param)
- `a3` -> `secondaryOwner` (from mangled name: second unique_ptr param)
- `v5`-`v8` -> descriptive names based on role (moved pointers, old values)
- `_QWORD *` -> proper types from mangled name decode
- Raw pointer arithmetic (`a1[1]`, `a1[2]`) -> struct field access
- `(**v7)(v7, 1)` -> `oldPrimary->Release(1)` (virtual destructor call recognized)
- Added struct reconstruction based on access pattern: 3 QWORD fields at offsets 0, 8, 16

---

## Example 2: Simple Command Handler Delegation

### Before (IDA output)

```cpp
// Function Name: eCopy
// Mangled Name: ?eCopy@@YAHPEAUcmdnode@@@Z
// Function Signature (Extended): __int64 __fastcall eCopy(struct cmdnode *)
// Function Signature: int eCopy(struct cmdnode *)

__int64 __fastcall eCopy(const unsigned __int16 **a1)
{
  __int64 result; // rax

  result = copy(a1[15]);
  LastRetCode = result;
  return result;
}
```

### After (Lifted)

```cpp
/**
 * eCopy - Handler for the built-in COPY command.
 *
 * Extracts the argument string from the command node and delegates
 * to copy() for actual file copying logic. Stores the result in
 * the global LastRetCode.
 *
 * @param cmd  Command node containing the COPY command and arguments
 * @return     Exit code from the copy operation
 */
int eCopy(struct cmdnode *cmd)
{
    // cmd->arguments is at offset 15 * 8 = 0x78
    int result = copy(cmd->arguments);
    LastRetCode = result;
    return result;
}
```

### Changes Made
- `a1` -> `cmd` (typed as `struct cmdnode *` per mangled name)
- `const unsigned __int16 **` -> `struct cmdnode *` (IDA mis-typed; mangled name proves correct type)
- `__int64` -> `int` (matches mangled name `YAH` = returns int)
- `a1[15]` -> `cmd->arguments` (offset 0x78 = arguments field, known from cross-referencing cmdnode accesses)
- Added doc block explaining purpose (inferred from function name + delegation to `copy()`)

---

## Example 3: Destructor with unique_ptr Cleanup

### Before (IDA output)

```cpp
// Function Name: BinaryAndStrategy::~BinaryAndStrategy
// Mangled Name: ??1BinaryAndStrategy@@UEAA@XZ
// Function Signature (Extended): void __fastcall BinaryAndStrategy::~BinaryAndStrategy(BinaryAndStrategy *__hidden this)
// Function Signature: public: virtual BinaryAndStrategy::~BinaryAndStrategy(void)
void __fastcall BinaryAndStrategy::~BinaryAndStrategy(BinaryAndStrategy *this)
{
  void (__fastcall ***v2)(_QWORD, __int64); // rcx
  void (__fastcall ***v3)(_QWORD, __int64); // rcx

  v2 = (void (__fastcall ***)(_QWORD, __int64))*((_QWORD *)this + 2);
  *((_QWORD *)this + 2) = 0;
  if ( v2 )
    (**v2)(v2, 1);
  v3 = (void (__fastcall ***)(_QWORD, __int64))*((_QWORD *)this + 1);
  *((_QWORD *)this + 1) = 0;
  if ( v3 )
    (**v3)(v3, 1);
}
```

### After (Lifted)

```cpp
/**
 * BinaryAndStrategy::~BinaryAndStrategy - Virtual destructor.
 *
 * Releases both rate limiter strategies in reverse order of
 * construction (secondary first, then primary). Each strategy
 * is nulled out before destruction to prevent double-free.
 *
 * @param this  Object being destroyed
 */
void BinaryAndStrategy::~BinaryAndStrategy(BinaryAndStrategy *this)
{
    // Destroy secondary strategy first (reverse construction order)
    RateLimiterStrategy *secondary = this->secondaryStrategy;  // +0x10
    this->secondaryStrategy = nullptr;
    if (secondary) {
        secondary->Release(1);  // invoke destructor via vtable slot 0
    }

    // Destroy primary strategy
    RateLimiterStrategy *primary = this->primaryStrategy;  // +0x08
    this->primaryStrategy = nullptr;
    if (primary) {
        primary->Release(1);  // invoke destructor via vtable slot 0
    }
}
```

### Changes Made
- `v2` -> `secondary`, `v3` -> `primary` (named by role; destruction is reverse order)
- `*((_QWORD *)this + 2)` -> `this->secondaryStrategy` (offset 0x10, consistent with constructor)
- `*((_QWORD *)this + 1)` -> `this->primaryStrategy` (offset 0x08)
- `(**v2)(v2, 1)` -> `secondary->Release(1)` (vtable virtual destructor call)
- Added note about reverse destruction order

---

## Example 4: Virtual Method with Boolean Logic

### Before (IDA output)

```cpp
// Function Name: BinaryAndStrategy::IsAllowed
// Mangled Name: ?IsAllowed@BinaryAndStrategy@@UEAA_NXZ
// Function Signature (Extended): bool __fastcall BinaryAndStrategy::IsAllowed(BinaryAndStrategy *__hidden this)
// Function Signature: public: virtual bool BinaryAndStrategy::IsAllowed(void)
bool __fastcall BinaryAndStrategy::IsAllowed(BinaryAndStrategy *this)
{
  char v2; // bl

  v2 = 0;
  if ( (*(unsigned __int8 (__fastcall **)(_QWORD))(**((_QWORD **)this + 1) + 8LL))(*((_QWORD *)this + 1)) )
    return (*(unsigned __int8 (__fastcall **)(_QWORD))(**((_QWORD **)this + 2) + 8LL))(*((_QWORD *)this + 2)) != 0;
  return v2;
}
```

### After (Lifted)

```cpp
/**
 * BinaryAndStrategy::IsAllowed - Checks if both rate limiters allow the operation.
 *
 * Implements a logical AND: returns true only if both the primary
 * and secondary strategies report that the operation is allowed.
 * Short-circuits if the primary strategy denies.
 *
 * @param this  BinaryAndStrategy object with two rate limiters
 * @return      true if both strategies allow, false otherwise
 */
bool BinaryAndStrategy::IsAllowed(BinaryAndStrategy *this)
{
    // Check primary strategy via virtual call to IsAllowed (vtable slot 1, offset +0x08)
    if (!this->primaryStrategy->IsAllowed()) {
        return false;
    }

    // Both must agree -- check secondary strategy
    return this->secondaryStrategy->IsAllowed();
}
```

### Changes Made
- `v2` eliminated (was just a `false` default, replaced by explicit `return false`)
- Complex vtable dispatch `(**((_QWORD **)this + 1) + 8LL)` decoded:
  - `*((_QWORD *)this + 1)` = `this->primaryStrategy` (offset 0x08)
  - Dereference to get vtable pointer, then `+8` = vtable slot 1 = `IsAllowed` virtual method
- Same pattern for secondary strategy at offset 0x10
- Short-circuit logic preserved exactly: if primary denies, return false immediately
- `char v2 = 0` + late return simplified to `return false`

---

## Example 5: main() Initialization (Partial)

### Before (IDA output, abbreviated)

```cpp
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  DWORD CurrentThreadId; // eax
  void *v4; // rcx
  int v5; // eax
  // ...
  CurrentThreadId = GetCurrentThreadId();
  hMainThread = OpenThread(0x1FFFFFu, 0, CurrentThreadId);
  CmdSetThreadUILanguage();
  HeapSetInformation(0, HeapEnableTerminationOnCorruption, 0, 0);
  GetCmdPolicy(Data);
  if ( *(_DWORD *)Data == 1 )
  {
    PutStdOut(0x40002729u, 0);
    ePause(0);
    CMDexit(255);
  }
```

### After (Lifted, abbreviated)

```cpp
#define CMD_POLICY_DISABLED     1
#define CMD_POLICY_INTERACTIVE  2
#define MSG_CMD_DISABLED        0x40002729u

/**
 * main - Entry point for cmd.exe.
 *
 * Initializes the command processor: sets up thread handle, locale,
 * heap protections, and checks group policy. Then enters the
 * parse-dispatch loop for interactive or batch mode.
 */
int __noreturn main(int argc, const char **argv, const char **envp)
{
    BYTE cmdPolicy[4] = {0};

    // Initialize thread handle for later suspension/signaling
    DWORD threadId = GetCurrentThreadId();
    hMainThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    CmdSetThreadUILanguage();

    // Enable heap corruption detection
    HeapSetInformation(NULL, HeapEnableTerminationOnCorruption, NULL, 0);

    // Check group policy: is cmd.exe disabled by administrator?
    GetCmdPolicy(cmdPolicy);

    if (*(DWORD *)cmdPolicy == CMD_POLICY_DISABLED) {
        PutStdOut(MSG_CMD_DISABLED, 0);  // "Command prompt has been disabled"
        ePause(0);
        CMDexit(255);
    }
    // ...
```

### Changes Made
- `0x1FFFFFu` -> `THREAD_ALL_ACCESS` (known Win32 constant)
- `0` -> `FALSE` / `NULL` where semantically appropriate
- `Data` -> `cmdPolicy` (based on usage with `GetCmdPolicy`)
- `*(_DWORD *)Data == 1` -> `*(DWORD *)cmdPolicy == CMD_POLICY_DISABLED`
- `0x40002729u` -> `MSG_CMD_DISABLED` constant with descriptive name
- Added block comments explaining initialization phases

---

## Example 6: Lock Pairs with Exception Handling

Demonstrates reconstructing `EnterCriticalSection`/`LeaveCriticalSection` paired with `__try`/`__finally`, ensuring lock release on all paths.

### Before (IDA output, synthesized)

```cpp
__int64 __fastcall sub_1800A3F00(__int64 a1, __int64 a2)
{
  __int64 v3; // rax
  __int64 v4; // rbx

  EnterCriticalSection(a1 + 0x40);
  v3 = *((_QWORD *)a1 + 4);
  if ( !v3 )
  {
    LeaveCriticalSection(a1 + 0x40);
    return 0x80004005;
  }
  v4 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)v3 + 0x18))(v3, a2);
  LeaveCriticalSection(a1 + 0x40);
  return v4;
}
```

### After (Lifted)

```cpp
// Reconstructed layout
struct SessionManager {
    QWORD field_00;                     // +0x00
    QWORD field_08;                     // +0x08
    QWORD field_10;                     // +0x10
    QWORD field_18;                     // +0x18
    ISessionHandler *activeHandler;     // +0x20  (QWORD slot 4)
    QWORD field_28;                     // +0x28
    QWORD field_30;                     // +0x30
    QWORD field_38;                     // +0x38
    CRITICAL_SECTION lock;              // +0x40
};

/**
 * SessionManager::DispatchRequest - Dispatches a request through the active handler.
 *
 * Acquires the session lock, checks that a handler is registered,
 * invokes the handler's ProcessRequest method (vtable slot 3), and
 * releases the lock. Returns E_FAIL if no handler is active.
 *
 * @param sessionMgr  Session manager owning the lock and handler reference
 * @param request     Request object to dispatch
 * @return            HRESULT from the handler, or E_FAIL if no handler
 */
HRESULT SessionManager::DispatchRequest(
    SessionManager *sessionMgr,
    IRequest *request)
{
    // Acquire session lock before accessing shared handler state
    EnterCriticalSection(&sessionMgr->lock);  // +0x40

    ISessionHandler *handler = sessionMgr->activeHandler;  // +0x20
    if (!handler) {
        // No active handler -- release lock and return failure
        LeaveCriticalSection(&sessionMgr->lock);
        return E_FAIL;
    }

    // Dispatch through vtable slot 3 (offset +0x18 = ProcessRequest)
    HRESULT hr = handler->ProcessRequest(request);

    LeaveCriticalSection(&sessionMgr->lock);
    return hr;
}
```

### Changes Made
- `a1` -> `sessionMgr` (inferred from lock at +0x40 and handler at +0x20)
- `a2` -> `request` (passed directly to virtual call)
- `sub_1800A3F00` -> `SessionManager::DispatchRequest` (inferred purpose)
- `0x80004005` -> `E_FAIL` (known HRESULT constant)
- `a1 + 0x40` -> `&sessionMgr->lock` (CRITICAL_SECTION at offset 0x40)
- `*((_QWORD *)a1 + 4)` -> `sessionMgr->activeHandler` (QWORD slot 4 = offset 0x20)
- `*(_QWORD *)v3 + 0x18` -> vtable slot 3 decoded as `ProcessRequest`
- Lock acquire/release verified on both exit paths (early return and normal return)

---

## Example 7: HRESULT Error Chain with Cleanup

Demonstrates lifting cascaded HRESULT checks with a shared cleanup label.

### Before (IDA output, synthesized)

```cpp
__int64 __fastcall sub_180042100(__int64 a1, unsigned __int16 *a2)
{
  int v3; // eax
  void *v4; // rax
  __int64 v5; // rbx
  int v6; // eax

  v3 = CoCreateInstance(&CLSID_TaskScheduler, 0, 0x17u, &IID_ITaskService, &v4);
  if ( v3 < 0 )
    return (unsigned int)v3;
  v5 = (__int64)v4;
  v6 = (*(int (__fastcall **)(__int64, _QWORD, _QWORD, _QWORD, _QWORD))(*(_QWORD *)v4 + 0x30))(
         (__int64)v4, 0, 0, 0, 0);
  if ( v6 < 0 )
    goto LABEL_5;
  v6 = (*(int (__fastcall **)(__int64, unsigned __int16 *, __int64 *))(*(_QWORD *)v5 + 0x38))(v5, a2, a1);
  if ( v6 < 0 )
    goto LABEL_5;
  v6 = 0;
LABEL_5:
  (*(void (__fastcall **)(__int64))(*(_QWORD *)v5 + 0x10))(v5);
  return (unsigned int)v6;
}
```

### After (Lifted)

```cpp
#define CLSCTX_LOCAL_SERVER_AND_INPROC  0x17u  // CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_HANDLER

/**
 * RegisterScheduledTask - Creates and registers a task via the Task Scheduler COM interface.
 *
 * Instantiates the Task Scheduler service, connects to it, then
 * registers the task at the specified folder path. Releases the
 * service object on all exit paths (success and failure).
 *
 * @param taskFolder  Output pointer receiving the registered task folder
 * @param folderPath  Path for the scheduled task (e.g., L"\\MyApp\\Maintenance")
 * @return            S_OK on success, or the HRESULT from the first failing call
 */
HRESULT RegisterScheduledTask(
    ITaskFolder **taskFolder,
    const wchar_t *folderPath)
{
    // Create Task Scheduler COM object
    ITaskService *taskService = NULL;
    HRESULT hr = CoCreateInstance(
        &CLSID_TaskScheduler, NULL, CLSCTX_LOCAL_SERVER_AND_INPROC,
        &IID_ITaskService, (void **)&taskService);
    if (FAILED(hr))
        return hr;

    // Connect to the local task service (vtable slot 6, offset +0x30)
    hr = taskService->Connect(NULL, NULL, NULL, NULL);
    if (FAILED(hr))
        goto cleanup;

    // Get the task folder at the specified path (vtable slot 7, offset +0x38)
    hr = taskService->GetFolder(folderPath, taskFolder);
    if (FAILED(hr))
        goto cleanup;

    hr = S_OK;

cleanup:
    // Always release the COM object, regardless of success or failure
    taskService->Release();  // vtable slot 2, offset +0x10
    return hr;
}
```

### Changes Made
- `a1` -> `taskFolder` (output pointer, receives result of GetFolder)
- `a2` -> `folderPath` (wchar_t path string passed to GetFolder)
- `sub_180042100` -> `RegisterScheduledTask` (inferred from COM CLSID + API sequence)
- `0x17u` -> `CLSCTX_LOCAL_SERVER_AND_INPROC` (named constant with flag breakdown)
- `v3 < 0` / `v6 < 0` -> `FAILED(hr)` (standard HRESULT macro)
- `v4` -> `taskService` (typed as `ITaskService *` from IID)
- `*(_QWORD *)v4 + 0x30` -> `taskService->Connect` (vtable slot 6 = ITaskService::Connect)
- `*(_QWORD *)v5 + 0x38` -> `taskService->GetFolder` (vtable slot 7)
- `*(_QWORD *)v5 + 0x10` -> `taskService->Release` (vtable slot 2 = IUnknown::Release)
- Cleanup goto preserved (represents real single-exit cleanup pattern)
- Added inline comments explaining each COM vtable slot and the overall flow

---

## Key Lifting Decisions

### When to Use `->` vs Pointer Arithmetic
- **Use `->` when** you have reconstructed the struct and named the fields
- **Keep raw arithmetic when** the struct is unknown or the offset doesn't map cleanly

### When to Preserve Original Types
- Keep `__int64` when it genuinely represents a 64-bit value (not a mistyped pointer)
- Replace with `int`, `HRESULT`, `BOOL`, etc., when the mangled name or usage reveals the true type

### When to Keep Gotos
- `setjmp`/`longjmp` error recovery -- real non-local jumps
- SEH `__try`/`__except` generated cleanup paths
- Complex switch-case fallthrough patterns where restructuring would change semantics
- HRESULT error chains with shared cleanup (as in Example 7)

### When to Reconstruct Structs
- 3+ accesses to the same base pointer at different offsets
- Cross-function consistency (same offsets used in related functions)
- VTable contexts confirm class hierarchy
