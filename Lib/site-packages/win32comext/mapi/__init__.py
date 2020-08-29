if type(__path__)==type(''):
	# For freeze to work!
	import sys
	try:
		from . import mapi
		sys.modules['win32com.mapi.mapi'] = mapi
	except ImportError:
		pass
	try:
		from . import exchange
		sys.modules['win32com.mapi.exchange'] = exchange
	except ImportError:
		pass
	try:
		import exchdapi
		sys.modules['win32com.mapi.exchdapi'] = exchdapi
	except ImportError:
		pass
else:
	import win32com
	# See if we have a special directory for the binaries (for developers)
	win32com.__PackageSupportBuildPath__(__path__)

