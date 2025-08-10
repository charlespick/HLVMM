$vm = New-HLVirtualMachine -VMName "New Virtual Machine" -Cluster (Get-Cluster -Name "MyCluster") -CPUCores 4 -MemoryGB 8 -VLANid 100

Add-HLVirtualDisk -VM $vm -DiskSizeGB 100
