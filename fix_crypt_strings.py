"""修复 crypt_strings.h 的 decrypt_to_wstring UTF-8转换BUG"""
import re

path = r"C:\Users\Administrator\Desktop\2026_8_19_1和4\02_守护进程注入方案\crypt_strings.h"

with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

old = """inline std::wstring decrypt_to_wstring(const EncryptedRecordBase& record) {
    std::string s = decrypt_to_string(record);
    return std::wstring(s.begin(), s.end());
}"""

new = """inline std::wstring decrypt_to_wstring(const EncryptedRecordBase& record) {
    unsigned char key[32];
    derive_record_key(record.nonce, key);
    std::vector<unsigned char> plaintext(record.length);
    chacha20_xor(key, record.nonce, 1, record.ciphertext, plaintext.data(), plaintext.size());
    std::fill(key, key + sizeof(key), 0);
    std::wstring result;
    if (record.is_wide) {
        // 密文解密后为 UTF-16LE 字节，直接构造 wstring
        size_t wchar_count = plaintext.size() / sizeof(wchar_t);
        result.assign(reinterpret_cast<const wchar_t*>(plaintext.data()), wchar_count);
    } else {
        // 密文解密后为 UTF-8 字节，用 MultiByteToWideChar 正确转换
        int len = MultiByteToWideChar(CP_UTF8, 0,
            reinterpret_cast<const char*>(plaintext.data()),
            static_cast<int>(plaintext.size()), NULL, 0);
        if (len > 0) {
            result.resize(len);
            MultiByteToWideChar(CP_UTF8, 0,
                reinterpret_cast<const char*>(plaintext.data()),
                static_cast<int>(plaintext.size()), &result[0], len);
        }
    }
    std::fill(plaintext.begin(), plaintext.end(), 0);
    return result;
}"""

if old in content:
    content = content.replace(old, new)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("OK: decrypt_to_wstring 已修复")
else:
    print("ERROR: 未找到目标代码块")