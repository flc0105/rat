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