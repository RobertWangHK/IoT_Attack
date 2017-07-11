import os
import time
import json

command_history = []
time_length = 3600
data_path = "../Data"

commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
			'on'       : '{"system":{"set_relay_state":{"state":1}}}',
			'off'      : '{"system":{"set_relay_state":{"state":0}}}',
			'cloudinfo': '{"cnCloud":{"get_info":{}}}',
			'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
			'time'     : '{"time":{"get_time":{}}}',
			'schedule' : '{"schedule":{"get_rules":{}}}',
			'countdown': '{"count_down":{"get_rules":{}}}',
			'antitheft': '{"anti_theft":{"get_rules":{}}}',
			'reboot'   : '{"system":{"reboot":{"delay":1}}}',
			'reset'    : '{"system":{"reset":{"delay":1}}}'
            }

class Control():
    def command_loop(self):
        """Test one set of available commands for the IoT light device in a loop manner"""
        keys = commands.keys()
        keys.remove("reset")
        keys.remove("reboot")
        for key in keys:
            command = "python TPLInk-Plugin/tplink-smartplug.py -t 192.168.1.4 -c " + str(key)
            command_history.append(str(key))
            os.system(command)
            time.sleep(5)

if __name__ == "__main__":
    control = Control()
    while(1):
        control.command_loop()
    with open(os.path.join(data_path,"command_labels"), "w") as output:
        json.dump(command_history, output)
    output.close()
