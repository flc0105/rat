SCRIPT_METADATA = {
    "name": "ios/recon/reminders",
    "display_name": "Dump Reminders",
    "description": "Retrieve all pending and completed reminders from the iOS Reminders app",
    "platforms": ["ios"],
    "category": "Recon",
    "params": []
}

import reminders

def main():
	todo = reminders.get_reminders(completed=False)
	print('TODO List\n=========')
	for r in todo:
		print('[ ] ' + r.title)
	done = reminders.get_reminders(completed=True)
	print('DONE\n====')
	for r in done:
		print('[x] ' + r.title)


main()