# EPIC_Attack_Datasets
This repository contains MiTM scripts for attacking generator synchronization and reverse power prevention operations in EPIC [1]. 

## Dependencies
Python libraries:
netfilterqueue
scapy

system libraries:
dsniff
ip-utils

## Usage

- Set ip according to subnet configuration
- Run arpspoof with respect to the targets (some attacks might need more than 2 instances of arpspoof):
- sudo arpspoof -i `interface` -t `target1` `target2`
- sudo arpspoof -i `interface` -t `target2` `target1`
- Enable attack in main (others commented out) and run:
- sudo python3 spoof_updated_HC_new.py

## Description of EPIC processes
1) Synchronization of generators:
- Operator clicks on sync check on dashboard
- Command Sync command is issued
- Upon issuing of sync command, the VSD (variable speed drive) associated with generator runs at 1500.4 rpm
- This allows for the phase angle between the generators to go to zero
- When phase angle is near zero, generators are synced. Q2C_In_Sync command is sent to lower the VSD speed to 1500.2 or 1500 rpm. Generator that was to be synced is now outputting power, it will continue increasing its power output till it reaches the threshold determined by the load sharing percentage

2) Reverse Power prevention:
- When Generator X is supplying negative power, GENX_P_Negative command from SPLC to MIEDX is set to True
- Upon setting to True, VSD associated with Generator X has its speed increased to 1500.2 and the other Generator has its speed set to 1500. 

## Attack Details

1) FDIA1: Spoof boolean value of SCADA Sync mms command from SCADA to SPLC to False. This prevents the plant from syncing
2) FDIA2: Spoof phase angle value to some other values which prevents operator from clicking on the box to finish sync process
3) TDA1: Delay setting of VSD speed to 1500.4. This prevents the generator from syncing as the phase angle cannot converge to 0. 
4) FDIA3: Set GEN1_P_Negative to False. Set VSD1 speed to 1500 and VSD2 speed to 1500.2 (opposite of reverse pw logic). This causes the generator to output negative power and eventually if attack is not released will cause the plant to trip. 
5) FDIA4: Set GEN2_P_Negative to True. Then set VSD2 speed to some value < 7500. This causes the generator to output negative power very quickly and eventually will cause the plant to trip. 
6) TDA2: Set GEN2_P_Negative to True. Then delay setting of VSD2 speed to 1500.2 (as specified by reverse power logic). This causes the generator to slowly decrease its power output till it supplies negative power and eventually will also cause the plant to trip. 

## References
[1] https://itrust.sutd.edu.sg/testbeds/electric-power-intelligent-control-epic/
