import paramiko
import os
import time

server_ip = "192.168.0.38"
username = "zainab"
password = "zainab123"

remote_folder = "/home/zainab/pcap"
local_folder = "resources/pcap"

os.makedirs(local_folder, exist_ok=True)

downloaded_files = set(
    f for f in os.listdir(local_folder)
    if f.endswith(".pcap")
)


def connect_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=server_ip,
        username=username,
        password=password,
        timeout=10,
    )
    print("[INFO] Connected to SSH server")
    return ssh


def list_pcap_files(ssh):
    cmd = f'echo "{password}" | sudo -S ls "{remote_folder}"'
    
    stdin, stdout, stderr = ssh.exec_command(cmd)

    exit_code = stdout.channel.recv_exit_status()

    files = stdout.read().decode().split()
    err = stderr.read().decode().strip()

    if exit_code != 0:
        print("[ERROR listing]")
        print(err)
        return []

    return [f for f in files if f.endswith(".pcap")]


def download_file(ssh, file):
    remote_path = f"{remote_folder}/{file}"
    local_path = os.path.join(local_folder, file)

    print(f"\n[INFO] Downloading {file}")

    cmd = f'echo "{password}" | sudo -S cat "{remote_path}"'

    stdin, stdout, stderr = ssh.exec_command(cmd)

    try:
        with open(local_path, "wb") as f:
            while True:
                data = stdout.channel.recv(32768)  # 32 KB
                if not data:
                    break
                f.write(data)

        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0:
            error = stderr.read().decode().strip()

            print(f"[ERROR] Failed to download {file}")
            print(error)

            if os.path.exists(local_path):
                os.remove(local_path)

            return False

        print(f"[SUCCESS] {file}")
        return True

    except Exception as e:
        print(f"[ERROR] {e}")

        if os.path.exists(local_path):
            os.remove(local_path)

        return False


def main():
    ssh = None

    while True:
        try:
            if ssh is None:
                ssh = connect_ssh()
                print("*****************")
            files = list_pcap_files(ssh)

            for file in files:
                if file not in downloaded_files:
                    if download_file(ssh, file):
                        downloaded_files.add(file)

                time.sleep(0)

        except Exception as e:
            print(f"[LOOP ERROR] {e}")

            try:
                if ssh:
                    ssh.close()
            except:
                pass

            ssh = None
            # time.sleep(5)
            time.sleep(0)

if __name__ == "__main__":
    main()
