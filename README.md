# Home Lab Virtual Machine Manager
Like System Center Virtual Machine Manager, but worse. 

**Advantages of using HLVMM**
* You don't need a SCVMM License
* You don't need SQL Server
* Not another thing to maintain in your homelab
* Lightweight - only runs on your workstation

**Disadvantages of using HLVMM**
* It basically only does template provisioning
* It kinda sucks - use at your own risk

**Why was everything recently deleted?**
I didn't like how this was going. I've decided to rework the entire project

Ansible/AWX is a frontend that cordinates the process now on the host

Playbooks are defined for each OS - this simplifies the logic in each OS by
delegating os specific behavior to individual playbooks

We now use a generic provisioning media (unattend or cloud-init) that delivers
the provisioning logic and provisioning data is delivered via KVP

Provisioning data is encrypted in KVP and readable only by the guest after the
key exchange process. This prevents credential leakage from failed provisioning
runs

The provisioning process ends with the guest now. The provisioning process is
much simplified
1. Host copies image and provisioning media and configures, boots VM
2. Guest initiates secure communication and gets it's data
3. Once host sends it's data, it's done
4. Guest finishes everything internally, doesn't need to signal anything to
the host with a shut down