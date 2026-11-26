"""
ChaCha Crypt - ChaCha20-Poly1305 でファイルを暗号化/復号するシンプルなツール

開発用(exe化するPCで1回だけ):
    pip install cryptography tkinterdnd2 pyinstaller
    build.bat でexe化すれば、配布先では何もインストール不要

ファイル形式 (.chacha):
    [ マジック "CHA1" 4B ][ Salt 16B ][ Nonce 12B ][ 暗号化チャンク ... ]
    - 鍵   : PBKDF2-HMAC-SHA256 (600,000回) で作った32バイト
    - 本体 : 1MiBごとに分割して ChaCha20-Poly1305 で暗号化 (各チャンクに16Bの認証タグ)
    - チャンクNonce : 先頭のNonceにチャンク番号をXORしたもの
    - AAD  : ヘッダ + 最終チャンクかどうかのフラグ (途中切り詰め・並び替えを検出)
"""
import hashlib
import os
import queue
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"CHA1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
ITERATIONS = 600_000
CHUNK = 1024 * 1024  # 1 MiB
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN
EXT = ".chacha"


class CryptError(Exception):
    pass


# ----------------------------------------------------------------- 暗号の中身
def derive_key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS, dklen=32)


def _chunk_nonce(base: bytes, index: int) -> bytes:
    n = bytearray(base)
    ctr = index.to_bytes(8, "little")
    for k in range(8):
        n[4 + k] ^= ctr[k]
    return bytes(n)


def _aad(header: bytes, is_last: bool) -> bytes:
    return header + (b"\x01" if is_last else b"\x00")


def check_password_text(password: str) -> bytes:
    """半角ASCII(スペース〜~)のみ許可。"""
    if not password:
        raise CryptError("パスワードを入力してください")
    if not all(32 <= ord(c) <= 126 for c in password):
        raise CryptError("パスワードは半角英数字と記号のみ使用できます")
    return password.encode("ascii")


def unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while True:
        cand = f"{base} ({i}){ext}"
        if not os.path.exists(cand):
            return cand
        i += 1


def encrypt_file(src: str, password: str, progress=None) -> str:
    pw = check_password_text(password)
    dst = unique_path(src + EXT)
    tmp = dst + ".tmp"

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce
    aead = ChaCha20Poly1305(derive_key(pw, salt))

    size = os.path.getsize(src)
    n_chunks = max(1, -(-size // CHUNK))
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            fo.write(header)
            for i in range(n_chunks):
                data = fi.read(CHUNK)
                last = i == n_chunks - 1
                fo.write(aead.encrypt(_chunk_nonce(nonce, i), data, _aad(header, last)))
                if progress:
                    progress(i + 1, n_chunks)
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return dst


def decrypt_file(src: str, password: str, progress=None) -> str:
    pw = check_password_text(password)
    if not src.lower().endswith(EXT):
        raise CryptError("拡張子が .chacha のファイルではありません")

    total = os.path.getsize(src)
    if total < HEADER_LEN + TAG_LEN:
        raise CryptError("ファイルが小さすぎます(破損している可能性があります)")

    with open(src, "rb") as fi:
        header = fi.read(HEADER_LEN)
        if header[:4] != MAGIC:
            raise CryptError("このツールで作成された .chacha ファイルではないようです")
        salt = header[4:4 + SALT_LEN]
        nonce = header[4 + SALT_LEN:]
        aead = ChaCha20Poly1305(derive_key(pw, salt))

        enc_size = total - HEADER_LEN
        step = CHUNK + TAG_LEN
        n_chunks = max(1, -(-enc_size // step))

        dst = unique_path(src[: -len(EXT)])
        tmp = dst + ".tmp"
        try:
            with open(tmp, "wb") as fo:
                for i in range(n_chunks):
                    last = i == n_chunks - 1
                    blob = fi.read(step)
                    try:
                        plain = aead.decrypt(_chunk_nonce(nonce, i), blob, _aad(header, last))
                    except InvalidTag:
                        if i == 0:
                            raise CryptError("パスワードが違うか、ファイルが破損しています")
                        raise CryptError("ファイルが破損しているか、改ざんされています")
                    fo.write(plain)
                    if progress:
                        progress(i + 1, n_chunks)
            os.replace(tmp, dst)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
    return dst


# ------------------------------------------------------------------------ GUI
ICON_NAME = "pyinstaller.ico"


def set_window_icon(root):
    """chacha_crypt.py(またはexe)と同じフォルダの pyinstaller.ico をタイトルバーのアイコンにする。"""
    try:
        import sys

        base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, ICON_NAME)
        if not os.path.isfile(path):
            path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), ICON_NAME)
        try:
            root.iconbitmap(default=path)
        except Exception:
            pass

        def apply():
            # Windowsに「タイトルバー用の小さいサイズ」と「大きいサイズ」を指定して読み込ませる
            try:
                import ctypes
                from ctypes import wintypes

                u = ctypes.windll.user32
                u.GetParent.restype = wintypes.HWND
                u.GetParent.argtypes = [wintypes.HWND]
                u.LoadImageW.restype = wintypes.HANDLE
                u.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                                         ctypes.c_int, ctypes.c_int, wintypes.UINT]
                u.SendMessageW.restype = ctypes.c_ssize_t
                u.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
                hwnd = u.GetParent(root.winfo_id())
                for kind, mx, my in ((0, 49, 50), (1, 11, 12)):  # ICON_SMALL / ICON_BIG
                    w, h = u.GetSystemMetrics(mx), u.GetSystemMetrics(my)
                    hicon = u.LoadImageW(None, path, 1, w, h, 0x10)  # IMAGE_ICON, LR_LOADFROMFILE
                    if hicon:
                        u.SendMessageW(hwnd, 0x0080, kind, hicon)  # WM_SETICON
            except Exception:
                pass

        root.update_idletasks()
        apply()
        root.after(150, apply)  # Tkが表示時にアイコンを戻すことがあるので、もう一度
    except Exception:
        pass  # アイコンが無くてもそのまま起動する


def main():
    import tkinter as tk
    from tkinter import messagebox, ttk

    from tkinterdnd2 import DND_FILES, TkinterDnD

    root = TkinterDnD.Tk()
    root.title("ChaCha Crypt")
    root.geometry("380x240")
    root.resizable(False, False)
    set_window_icon(root)
    try:
        ttk.Style().theme_use("winnative")  # レガシーなWindows風
    except tk.TclError:
        pass

    container = tk.Frame(root)
    container.pack(fill="both", expand=True)
    q: "queue.Queue" = queue.Queue()
    state = {"busy": False}

    def clear():
        for w in container.winfo_children():
            w.destroy()

    # ---- 画面1: ドラッグアンドドロップ
    def show_drop():
        clear()
        state["busy"] = False
        lbl = tk.Label(container, text="暗号化または復号するファイルを\nドラッグアンドドロップ", justify="center",
                       font=("MS UI Gothic", 14),
                       relief="sunken", bd=2)
        lbl.pack(fill="both", expand=True, padx=12, pady=12)
        for w in (lbl, container):
            w.drop_target_register(DND_FILES)
            w.dnd_bind("<<Drop>>", on_drop)

    def on_drop(event):
        if state["busy"]:
            return
        files = root.tk.splitlist(event.data)
        if not files:
            return
        path = files[0]
        if not os.path.isfile(path):
            messagebox.showerror("ChaCha Crypt", "ファイルを入れてください(フォルダには未対応です)")
            return
        show_password(path)

    # ---- 画面2: パスワード入力
    def show_password(path):
        clear()
        decrypt = path.lower().endswith(EXT)
        tk.Label(container, text=os.path.basename(path), anchor="w").pack(fill="x", padx=12, pady=(14, 0))
        tk.Label(container, text="パスワード(半角のみ):" + ("  [復号]" if decrypt else "  [暗号化]"),
                 anchor="w").pack(fill="x", padx=12, pady=(8, 2))

        def only_ascii(proposed):
            return all(32 <= ord(c) <= 126 for c in proposed)

        vcmd = (root.register(only_ascii), "%P")
        ent = tk.Entry(container, show="*", validate="key", validatecommand=vcmd)
        ent.pack(fill="x", padx=12)
        ent.focus_set()
        ent2 = None
        if not decrypt:  # 暗号化のときだけ確認用の入力欄
            tk.Label(container, text="もう一度入力してください(確認):", anchor="w").pack(fill="x", padx=12, pady=(8, 2))
            ent2 = tk.Entry(container, show="*", validate="key", validatecommand=vcmd)
            ent2.pack(fill="x", padx=12)

        def go(_event=None):
            pw = ent.get()
            if ent2 is not None and ent2.get() != pw:
                messagebox.showerror("ChaCha Crypt", "確認用のパスワードが一致しません")
                return
            try:
                check_password_text(pw)
            except CryptError as e:
                messagebox.showerror("ChaCha Crypt", str(e))
                return
            start(path, pw, decrypt)

        ent.bind("<Return>", go)
        if ent2 is not None:
            ent2.bind("<Return>", go)
        btns = tk.Frame(container)
        btns.pack(pady=14)
        tk.Button(btns, text="OK", width=10, command=go).pack(side="left", padx=6)
        tk.Button(btns, text="キャンセル", width=10, command=show_drop).pack(side="left", padx=6)

    # ---- 画面3: プログレスバー
    def start(path, pw, decrypt):
        clear()
        state["busy"] = True
        tk.Label(container, text="復号中..." if decrypt else "暗号化中...").pack(pady=(40, 6))
        pb = ttk.Progressbar(container, length=300, mode="determinate", maximum=100)
        pb.pack()
        pct = tk.Label(container, text="鍵を生成中...")
        pct.pack(pady=6)

        def cb(done, total):
            q.put(("progress", done, total))

        def work():
            try:
                fn = decrypt_file if decrypt else encrypt_file
                out = fn(path, pw, cb)
                q.put(("done", out))
            except CryptError as e:
                q.put(("error", str(e), path))
            except Exception as e:  # noqa: BLE001
                q.put(("error", f"エラー: {e}", path))

        threading.Thread(target=work, daemon=True).start()

        def poll():
            try:
                while True:
                    msg = q.get_nowait()
                    if msg[0] == "progress":
                        pb["value"] = msg[1] * 100 / msg[2]
                        pct["text"] = f"{int(pb['value'])}%"
                    elif msg[0] == "done":
                        messagebox.showinfo("ChaCha Crypt", f"完了しました:\n{msg[1]}")
                        show_drop()
                        return
                    elif msg[0] == "error":
                        messagebox.showerror("ChaCha Crypt", msg[1])
                        show_password(msg[2])
                        state["busy"] = False
                        return
            except queue.Empty:
                pass
            root.after(50, poll)

        poll()

    show_drop()
    root.mainloop()


if __name__ == "__main__":
    main()
