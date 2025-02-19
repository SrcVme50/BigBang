import argparse
import base64

def convert_to_hashcat_format(email, password_hash, salt):
    # 将十六进制的密码哈希转换为字节
    decodedHash = bytes.fromhex(password_hash)

    # 将哈希值和盐值转换为 Base64 编码
    hashB64 = base64.b64encode(decodedHash).decode('utf-8')
    saltB64 = base64.b64encode(bytes(salt, 'utf-8')).decode('utf-8')

    # 输出符合 Hashcat 格式的字符串
    return f"sha256:10000:{saltB64}:{hashB64}"

def main():
    # 设置命令行参数解析
    parser = argparse.ArgumentParser(description="将用户的哈希和盐值转换为 Hashcat 可用的格式")
    parser.add_argument("-e", "--email", required=True, help="用户的电子邮件地址")
    parser.add_argument("-p", "--password-hash", required=True, help="用户的密码哈希（十六进制）")
    parser.add_argument("-s", "--salt", required=True, help="用户的盐值")

    args = parser.parse_args()

    # 调用转换函数
    result = convert_to_hashcat_format(args.email, args.password_hash, args.salt)

    # 打印 Hashcat 格式
    print(result)

if __name__ == "__main__":
    main()
