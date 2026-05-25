// trainer.cpp - External trainer, single exe
// Trampoline hook via VirtualAllocEx + WriteProcessMemory
//
// Hook 1: game.exe+33FFAE
//   Original:  89 87 A8 01 00 00   mov [edi+000001A8], eax
//   Cave:      mov dword ptr [edi+000001A8], 99
//              jmp back to game.exe+33FFB4
//
// Hook 2: game.exe+341CE9
//   Original:  89 86 A8 01 00 00   mov [esi+000001A8], eax
//   Cave:      mov dword ptr [esi+000001A8], 99
//              jmp back to game.exe+341CEF
//
// Link: d3d9.lib
// Compile: x86 EXE, /SUBSYSTEM:WINDOWS

#include <Windows.h>
#include <TlHelp32.h>
#include <d3d9.h>
#pragma comment(lib, "d3d9.lib")

#define STB_IMAGE_IMPLEMENTATION
#include "lib/stb_image.h"

#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx9.h"

#include "res/resource.h"
#include <vector>

// ── Game / hook constants ─────────────────────────────────────────────────────
constexpr const char* GAME_EXE = "game.exe";

// ── Process state ─────────────────────────────────────────────────────────────
static HANDLE    g_hProcess = nullptr;
static uintptr_t g_moduleBase = 0;

static bool g_infinite_reinforcments_enabled = false;
static bool g_instant_reinforcments_enabled = false;

// ── Visual settings ───────────────────────────────────────────────────────────
constexpr const char* WINDOW_TITLE = "ItsWolf | Blitzkrieg 2 | v1.0.0";

static LPDIRECT3DTEXTURE9 g_logo = nullptr;
static int                g_logoWidth = 0;
static int                g_logoHeight = 0;

// ── Generic trampoline hook ───────────────────────────────────────────────────
//
//  Each Hook instance owns:
//    - the offset inside the module where the original instruction lives
//    - the size of the bytes to overwrite (must be >= 5 for a rel32 jmp)
//    - the payload to execute in the code cave (caller-supplied bytes)
//    - saved original bytes so we can restore on disable
//    - the address of the allocated code cave in the target process
//
//  EnableHook():
//    1. Reads + saves the original bytes at hookAddr.
//    2. Allocates an executable code cave in the target process (VirtualAllocEx).
//    3. Writes:  <payload bytes>  +  E9 <rel32 back to hookAddr+hookSize>
//    4. Overwrites hookAddr with:  E9 <rel32 to cave>  +  NOPs for padding.
//
//  DisableHook():
//    1. Restores the saved original bytes.
//    2. Frees the code cave.

struct Hook
{
    // ── Configuration (set before calling Enable) ─────────────────────────
    uintptr_t offset = 0;      // RVA inside game.exe
    int       hookSize = 6;      // bytes to overwrite at hook site (>= 5)

    // Cave payload: the instruction(s) that replace the hooked instruction.
    // Do NOT include the trailing jmp-back here; EnableHook appends it.
    std::vector<BYTE> payload;

    // ── Runtime state ──────────────────────────────────────────────────────
    BYTE      originalBytes[16] = {};
    uintptr_t caveAddr = 0;
    bool      hooked = false;

    // ── Enable ─────────────────────────────────────────────────────────────
    bool Enable(HANDLE hProcess, uintptr_t moduleBase)
    {
        if (hooked || !hProcess) return false;

        uintptr_t hookAddr = moduleBase + offset;
        uintptr_t returnAddr = hookAddr + hookSize;

        // Save original bytes so we can restore later
        ReadProcessMemory(hProcess, (LPCVOID)hookAddr,
            originalBytes, hookSize, nullptr);

        // Allocate code cave (64 bytes is plenty for payload + jmp-back)
        LPVOID cave = VirtualAllocEx(hProcess, nullptr, 64,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (!cave) return false;
        caveAddr = (uintptr_t)cave;

        // Build the full cave: payload + jmp-back
        std::vector<BYTE> caveBytes;
        caveBytes.reserve(payload.size() + 5);
        caveBytes.insert(caveBytes.end(), payload.begin(), payload.end());

        // E9 <rel32>  — relative jmp back to the instruction after the hook
        INT32 rel = (INT32)(returnAddr - (caveAddr + caveBytes.size() + 5));
        caveBytes.push_back(0xE9);
        caveBytes.push_back((BYTE)(rel >> 0));
        caveBytes.push_back((BYTE)(rel >> 8));
        caveBytes.push_back((BYTE)(rel >> 16));
        caveBytes.push_back((BYTE)(rel >> 24));

        WriteProcessMemory(hProcess, cave,
            caveBytes.data(), caveBytes.size(), nullptr);

        // Patch the hook site: E9 <rel32 to cave> + NOPs for any leftover bytes
        std::vector<BYTE> patch(hookSize, 0x90); // fill with NOPs first
        INT32 jmpRel = (INT32)(caveAddr - (hookAddr + 5));
        patch[0] = 0xE9;
        patch[1] = (BYTE)(jmpRel >> 0);
        patch[2] = (BYTE)(jmpRel >> 8);
        patch[3] = (BYTE)(jmpRel >> 16);
        patch[4] = (BYTE)(jmpRel >> 24);

        DWORD oldProtect;
        VirtualProtectEx(hProcess, (LPVOID)hookAddr, hookSize,
            PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProcess, (LPVOID)hookAddr,
            patch.data(), hookSize, nullptr);
        VirtualProtectEx(hProcess, (LPVOID)hookAddr, hookSize,
            oldProtect, &oldProtect);

        hooked = true;
        return true;
    }

    // ── Disable ────────────────────────────────────────────────────────────
    void Disable(HANDLE hProcess, uintptr_t moduleBase)
    {
        if (!hooked || !hProcess) return;

        uintptr_t hookAddr = moduleBase + offset;

        DWORD oldProtect;
        VirtualProtectEx(hProcess, (LPVOID)hookAddr, hookSize,
            PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(hProcess, (LPVOID)hookAddr,
            originalBytes, hookSize, nullptr);
        VirtualProtectEx(hProcess, (LPVOID)hookAddr, hookSize,
            oldProtect, &oldProtect);

        VirtualFreeEx(hProcess, (LPVOID)caveAddr, 0, MEM_RELEASE);
        caveAddr = 0;
        hooked = false;
    }

    // ── Force-clear without restoring (use when target process has died) ──
    void Reset()
    {
        caveAddr = 0;
        hooked = false;
    }
};

// ── Hook instances ────────────────────────────────────────────────────────────
//
//  Both hooks force-write 99 (0x63) into the reinforcement counter field
//  (offset 0x1A8 from the unit base pointer) and then jump back to normal
//  execution, giving the player perpetually full reinforcements.
//
//  Hook 1 — game.exe+33FFAE
//    Original: 89 87 A8 01 00 00  →  mov [edi+000001A8], eax
//    Cave payload: C7 87 A8 01 00 00 63 00 00 00
//                  → mov dword ptr [edi+000001A8], 99
//
//  Hook 2 — game.exe+341CE9
//    Original: 89 86 A8 01 00 00  →  mov [esi+000001A8], eax
//    Cave payload: C7 86 A8 01 00 00 63 00 00 00
//                  → mov dword ptr [esi+000001A8], 99

static Hook g_hookReinf1 = {
    /* offset   */ 0x33FFAE,
    /* hookSize */ 6,
    /* payload  */ {
        // mov dword ptr [edi+000001A8], 63h  (99 reinforcements)
        0xC7, 0x87,
        0xA8, 0x01, 0x00, 0x00,   // disp32: +0x1A8
        0x63, 0x00, 0x00, 0x00    // imm32:  99
    }
};

static Hook g_hookReinf2 = {
    /* offset   */ 0x341CE9,
    /* hookSize */ 6,
    /* payload  */ {
        // mov dword ptr [esi+000001A8], 63h  (99 reinforcements)
        // identical encoding but ModRM byte 0x86 targets [esi+disp32]
        // instead of 0x87 which targets [edi+disp32]
        0xC7, 0x86,
        0xA8, 0x01, 0x00, 0x00,   // disp32: +0x1A8
        0x63, 0x00, 0x00, 0x00    // imm32:  99
    }
};

// Convenience wrappers that act on both reinforcement hooks together
void EnableInfiniteReinforcements()
{
    g_hookReinf1.Enable(g_hProcess, g_moduleBase);
    g_hookReinf2.Enable(g_hProcess, g_moduleBase);
}

void DisableInfiniteReinforcements()
{
    g_hookReinf1.Disable(g_hProcess, g_moduleBase);
    g_hookReinf2.Disable(g_hProcess, g_moduleBase);
}

void ResetAllHooks()
{
    g_hookReinf1.Reset();
    g_hookReinf2.Reset();
}

// ── Process helpers ───────────────────────────────────────────────────────────
DWORD GetProcessID() {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe{ sizeof(pe) };
    if (Process32First(snap, &pe))
        do { if (!_stricmp(pe.szExeFile, GAME_EXE)) { pid = pe.th32ProcessID; break; } } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

uintptr_t GetModuleBase(DWORD pid) {
    uintptr_t base = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32 me{ sizeof(me) };
    if (Module32First(snap, &me))
        do { if (!_stricmp(me.szModule, GAME_EXE)) { base = (uintptr_t)me.modBaseAddr; break; } } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

bool AttachToGame() {
    DWORD pid = GetProcessID();
    if (!pid) return false;
    g_moduleBase = GetModuleBase(pid);
    if (!g_moduleBase) return false;
    g_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return g_hProcess != nullptr;
}

void DetachFromGame() {
    if (g_hProcess) { CloseHandle(g_hProcess); g_hProcess = nullptr; }
    g_moduleBase = 0;
}

bool IsGameRunning() {
    if (!g_hProcess) return false;
    DWORD code;
    return GetExitCodeProcess(g_hProcess, &code) && code == STILL_ACTIVE;
}

bool LoadTextureFromResource(
    LPDIRECT3DDEVICE9   device,
    int                 resourceID,
    LPDIRECT3DTEXTURE9* out_texture,
    int* out_width,
    int* out_height)
{
    HRSRC res = FindResource(NULL, MAKEINTRESOURCE(resourceID), "PNG");
    if (!res) return false;

    HGLOBAL resHandle = LoadResource(NULL, res);
    if (!resHandle) return false;

    DWORD resSize = SizeofResource(NULL, res);
    void* resData = LockResource(resHandle);
    if (!resData) return false;

    int width = 0, height = 0;
    unsigned char* image_data = stbi_load_from_memory(
        (stbi_uc*)resData, resSize, &width, &height, NULL, 4);
    if (!image_data) return false;

    LPDIRECT3DTEXTURE9 texture = nullptr;
    if (device->CreateTexture(width, height, 1, D3DUSAGE_DYNAMIC,
        D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT,
        &texture, NULL) < 0)
    {
        stbi_image_free(image_data);
        return false;
    }

    D3DLOCKED_RECT rect;
    texture->LockRect(0, &rect, NULL, 0);
    for (int y = 0; y < height; y++)
        memcpy((unsigned char*)rect.pBits + rect.Pitch * y,
            image_data + (width * 4 * y), width * 4);
    texture->UnlockRect(0);
    stbi_image_free(image_data);

    *out_texture = texture;
    *out_width = width;
    *out_height = height;
    return true;
}

// ── Cheats implementation ─────────────────────────────────────────────────────

void InstantReinforcments(bool enable)
{
    // game.exe+1A7EA2  mov [esi+40],eax  →  90 90 90 (nop x3)
    uintptr_t targetAddr = g_moduleBase + 0x1A7EA2;
    constexpr int write_size = 3;

    DWORD oldProtect;
    if (enable)
    {
        BYTE patch[3] = { 0x90, 0x90, 0x90 };
        VirtualProtectEx(g_hProcess, (LPVOID)targetAddr, write_size, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(g_hProcess, (LPVOID)targetAddr, patch, write_size, nullptr);
        VirtualProtectEx(g_hProcess, (LPVOID)targetAddr, write_size, oldProtect, &oldProtect);
    }
    else
    {
        BYTE original[3] = { 0x89, 0x46, 0x40 };
        VirtualProtectEx(g_hProcess, (LPVOID)targetAddr, write_size, PAGE_EXECUTE_READWRITE, &oldProtect);
        WriteProcessMemory(g_hProcess, (LPVOID)targetAddr, original, write_size, nullptr);
        VirtualProtectEx(g_hProcess, (LPVOID)targetAddr, write_size, oldProtect, &oldProtect);
    }
}

// ── DX9 ───────────────────────────────────────────────────────────────────────
static HWND                  g_hwnd = nullptr;
static LPDIRECT3D9           g_pD3D = nullptr;
static LPDIRECT3DDEVICE9     g_pd3dDevice = nullptr;
static D3DPRESENT_PARAMETERS g_d3dpp = {};

bool CreateDeviceD3D(HWND hWnd) {
    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!g_pD3D) return false;
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd,
        D3DCREATE_HARDWARE_VERTEXPROCESSING,
        &g_d3dpp, &g_pd3dDevice) < 0)
        return false;
    return true;
}

void CleanupDeviceD3D() {
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release();       g_pD3D = nullptr; }
}

void ResetDevice() {
    ImGui_ImplDX9_InvalidateDeviceObjects();
    g_pd3dDevice->Reset(&g_d3dpp);
    ImGui_ImplDX9_CreateDeviceObjects();
}

// ── WndProc ───────────────────────────────────────────────────────────────────
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ── Entry point ───────────────────────────────────────────────────────────────
int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    WNDCLASSEX wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0,
        GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
        WINDOW_TITLE, nullptr };
    RegisterClassEx(&wc);

    g_hwnd = CreateWindow(
        wc.lpszClassName, WINDOW_TITLE,
        WS_POPUP,
        100, 100,
        520, 360,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);

    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    ImGui::StyleColorsDark();
    ImGui::GetStyle().WindowRounding = 6.f;
    ImGui::GetStyle().FrameRounding = 4.f;

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    LoadTextureFromResource(g_pd3dDevice, IDB_LOGO,
        &g_logo, &g_logoWidth, &g_logoHeight);

    bool open = true;
    MSG  msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        // Check if game closed mid-session
        if (g_hProcess && !IsGameRunning()) {
            // Process is gone — no point trying to write back, just clear state
            ResetAllHooks();

            g_infinite_reinforcments_enabled = false;
            g_instant_reinforcments_enabled = false;

            DetachFromGame();
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_FirstUseEver);
        ImGui::Begin(WINDOW_TITLE, &open,
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoSavedSettings);

        // Sync OS window position with ImGui title-bar dragging
        ImVec2 imguiWinPos = ImGui::GetWindowPos();
        if (imguiWinPos.x != 0.0f || imguiWinPos.y != 0.0f) {
            RECT winRect;
            if (GetWindowRect(g_hwnd, &winRect)) {
                int newX = winRect.left + static_cast<int>(imguiWinPos.x);
                int newY = winRect.top + static_cast<int>(imguiWinPos.y);
                SetWindowPos(g_hwnd, nullptr, newX, newY, 0, 0,
                    SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            }
            ImGui::SetWindowPos(WINDOW_TITLE, ImVec2(0, 0));
        }

        // ── Status / logo ─────────────────────────────────────────────────
        if (g_logo)
        {
            ImGui::Image((ImTextureID)g_logo, ImVec2(64, 64));
            ImGui::SameLine();
        }

        ImGui::BeginGroup();

        bool attached = g_hProcess && IsGameRunning();
        if (attached) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 1.f, 0.2f, 1.f));
            ImGui::Text("game.exe  [attached]");
            ImGui::PopStyleColor();
        }
        else {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.f, 0.4f, 0.4f, 1.f));
            ImGui::Text("game.exe  [Blitzkrieg 2 not attached]");
            ImGui::PopStyleColor();

            if (ImGui::Button("Attach to game", ImVec2(150, 24)))
                AttachToGame();
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.f));
            ImGui::Text("First launch the game, then attach trainer");
            ImGui::PopStyleColor();
        }

        ImGui::EndGroup();

        ImGui::Text("Cheats");
        ImGui::Separator();
        ImGui::Spacing();

        // ── Cheat toggles ─────────────────────────────────────────────────
        ImGui::Spacing();

        if (!attached) ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.4f);

        if (ImGui::Checkbox("Infinite Reinforcements", &g_infinite_reinforcments_enabled)) {
            if (attached) {
                if (g_infinite_reinforcments_enabled) EnableInfiniteReinforcements();
                else                                  DisableInfiniteReinforcements();
            }
            else {
                g_infinite_reinforcments_enabled = false;
            }
        }

        if (ImGui::Checkbox("Instant Reinforcements", &g_instant_reinforcments_enabled)) {
            if (attached) {
                InstantReinforcments(g_instant_reinforcments_enabled);
            }
            else {
                g_instant_reinforcments_enabled = false;
            }
        }

        if (!attached) ImGui::PopStyleVar();

        // ── Bottom Footer Links ───────────────────────────────────────────
        // Force the layout cursor to the bottom of the window
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 30.0f);
        ImGui::Separator();

        // Use a nice, muted gray text color
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.55f, 1.0f));

        // GitHub Link
        if (ImGui::Selectable("GitHub", false, 0, ImGui::CalcTextSize("GitHub"))) {
            ShellExecuteA(nullptr, "open", "https://github.com/yourusername", nullptr, nullptr, SW_SHOWNORMAL);
        }

        // Horizontal spacing between items
        ImGui::SameLine();
        ImGui::Text("|");
        ImGui::SameLine();

        // Website Link
        if (ImGui::Selectable("Website", false, 0, ImGui::CalcTextSize("Website"))) {
            ShellExecuteA(nullptr, "open", "https://yourwebsite.com", nullptr, nullptr, SW_SHOWNORMAL);
        }

        ImGui::PopStyleColor();

        ImGui::End();
        ImGui::EndFrame();

        g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.f, 0);
        if (g_pd3dDevice->BeginScene() >= 0) {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
        HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST &&
            g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();

        if (!open) msg.message = WM_QUIT;
    }

    // Always restore hooks before exit (if game is still alive)
    DisableInfiniteReinforcements();
    DetachFromGame();

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    if (g_logo) { g_logo->Release(); g_logo = nullptr; }

    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);
    return 0;
}