ST-Ericsson Android FM Handler for V4L2 devices
Author: marco.sinigaglia@csr.com for CSR plc


This is the V4L2 handler (or plugin) for the ST-Ericsson Android FM stack. 
SE stack source code at https://review.source.android.com/#change,20507.

The SE FM stack needs a component called "vendor specific handler" in order to work with a specific FM chip.
This handler implements the V4L2 standard, it allows to run any V4L2 FM compilant devices with the SE stack. 

The V4L2 standard does not have API for some FM features like: scan on chip, chip standby, set rssi threshold, chip tunned in a valid channel, RDS AF features.
These FM features have been implemented on the handler in order to not break the V4L2 standard. On the other hand, this is not an efficient approach.

Not all the API have been implemented yet.

The handler have been tested using the FM app released by SE: repo download platform/development 21829/1


Handler v0.1 RELEASE NOTE

IMPLEMENTED API v0.1
  -tx_start 
  -reset 
  -pause 
  -resume 
  -set_frequency 
  -get_frequency 
  -get_signal_strength 
  -get_threshold 
  -set_threshold 
  -is_tuned_to_valid_channel 
  -scan 
  -full_scan 
  -stop_scan 
  -on_rds_data_found. Only RDS PSN has been implemented

TODO  
  -on_rds_data_found. RDS
  -on_signal_strength_changed 
  -on_playing_in_stereo_changed 
  -on_automatic_switch 
  -set_automatic_af_switching 
  -set_automatic_ta_switching 
  -set_rds_data 
  -block_scan 



