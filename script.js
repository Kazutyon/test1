// script.js – RSA 手動計算デモ
// すべての数値は BigInt で扱うため、入力は文字列に変換してから BigInt に変換します。

// ---------- ユーティリティ ----------
function toBigInt(val) {
  // 空文字列や null は 0 に変換して安全に扱う
  return BigInt(val ? val.trim() : "0");
}

// 拡張ユークリッドアルゴリズム (a, b) -> {gcd, x, y} で x*a + y*b = gcd
function egcd(a, b) {
  if (b === 0n) return {g: a, x: 1n, y: 0n};
  const {g, x: x1, y: y1} = egcd(b, a % b);
  return {g, x: y1, y: x1 - (a / b) * y1};
}

function modInv(e, phi) {
  const {g, x} = egcd(e, phi);
  if (g !== 1n) throw new Error("e と φ(N) が互いに素でありません");
  // x が負の場合は phi で正規化
  return (x % phi + phi) % phi;
}

function modPow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function showFade(element, text) {
  element.textContent = text;
  element.classList.remove("show");
  // reflow to restart animation
  void element.offsetWidth;
  element.classList.add("show");
}

// ---------- 鍵生成 ----------
document.getElementById("gen-keys").addEventListener("click", () => {
  try {
    const p = toBigInt(document.getElementById("p").value);
    const q = toBigInt(document.getElementById("q").value);
    const e = toBigInt(document.getElementById("e").value);
    if (p <= 1n || q <= 1n) throw new Error("p と q は素数である必要があります");
    const N = p * q;
    const phi = (p - 1n) * (q - 1n);
    const d = modInv(e, phi);
    const out = `N = ${N}\nφ(N) = ${phi}\n公開鍵 (e, N) = (${e}, ${N})\n秘密鍵 (d, N) = (${d}, ${N})`;
    showFade(document.getElementById("keys-output"), out);
    // 保存して後続計算でも使えるように global へ
    window.rsa = {p, q, N, e, d, phi};
  } catch (err) {
    alert(err.message);
  }
});

// ---------- 暗号化 / 復号 ----------
document.getElementById("encrypt").addEventListener("click", () => {
  try {
    if (!window.rsa) throw new Error("先に鍵を生成してください");
    const m = toBigInt(document.getElementById("plain").value);
    if (m < 0n || m >= window.rsa.N) throw new Error("平文は 0 <= m < N の範囲で入力してください");
    const c = modPow(m, window.rsa.e, window.rsa.N);
    showFade(document.getElementById("cipher-output"), `暗号文 = ${c}`);
    window.rsa.lastPlain = m;
    window.rsa.lastCipher = c;
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById("decrypt").addEventListener("click", () => {
  try {
    if (!window.rsa || window.rsa.lastCipher === undefined) throw new Error("暗号化した後に復号してください");
    const m2 = modPow(window.rsa.lastCipher, window.rsa.d, window.rsa.N);
    showFade(document.getElementById("plain-output"), `復号結果 = ${m2}`);
  } catch (err) {
    alert(err.message);
  }
});

// ---------- 署名 / 検証 ----------
document.getElementById("signBtn").addEventListener("click", () => {
  try {
    if (!window.rsa) throw new Error("先に鍵を生成してください");
    const msg = toBigInt(document.getElementById("signPlain").value);
    if (msg < 0n || msg >= window.rsa.N) throw new Error("メッセージは 0 <= m < N の範囲で入力してください");
    const sig = modPow(msg, window.rsa.d, window.rsa.N);
    showFade(document.getElementById("signOutput"), `署名 = ${sig}`);
    window.rsa.lastSignMsg = msg;
    window.rsa.lastSignature = sig;
  } catch (err) {
    alert(err.message);
  }
});

document.getElementById("verifyBtn").addEventListener("click", () => {
  try {
    if (!window.rsa || window.rsa.lastSignature === undefined) throw new Error("署名した後に検証してください");
    const mPrime = modPow(window.rsa.lastSignature, window.rsa.e, window.rsa.N);
    const ok = mPrime === window.rsa.lastSignMsg;
    showFade(document.getElementById("verifyResult"), ok ? "検証成功：署名は有効です" : "検証失敗：署名が一致しません");
  } catch (err) {
    alert(err.message);
  }
});
