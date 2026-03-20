import paramiko
import sys

def run_ssh_commands(host, username, password, commands):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=username, password=password)
        
        for cmd in commands:
            print(f"--- Running: {cmd} ---")
            # Use sudo -S to read password from stdin
            full_cmd = f"echo {password} | sudo -S {cmd}"
            stdin, stdout, stderr = client.exec_command(full_cmd)
            
            # Print output
            out = stdout.read().decode()
            err = stderr.read().decode()
            if out: print(out)
            if err: 
                # Filter out the sudo password prompt
                clean_err = "\n".join([line for line in err.splitlines() if "[sudo] password for" not in line])
                if clean_err: print(clean_err)
            print("-" * 40)
            
        client.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    host = "192.168.1.153"
    user = "rsavage"
    pw = "no12trust"
    
    cmds = [
        "systemctl stop kubelet",
        "systemctl stop containerd",
        "rm -rf /var/lib/containerd/io.containerd.metadata.v1.bolt",
        "systemctl start containerd",
        "sleep 5",
        "systemctl status containerd",
        "systemctl start kubelet",
        "sleep 5",
        "systemctl status kubelet"
    ]
    
    run_ssh_commands(host, user, pw, cmds)
