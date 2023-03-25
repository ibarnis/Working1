
from logging import Formatter, Handler
import logging
import sys
from capture_for_validation import Capture_And_Compare
import servicemanager
import win32event
import win32service
import win32serviceutil
import pyuac
import logging
import datetime
import subprocees
def _main():
	
	_configure_logging()
	
	if len(sys.argv) == 1 and \
			sys.argv[0].endswith('.exe') and \
			not sys.argv[0].endswith(r'win32\PythonService.exe'):
		# invoked as non-pywin32-PythonService.exe executable without
		# arguments
		
		# We assume here that we were invoked by the Windows Service
		# Control Manager (SCM) as a PyInstaller executable in order to
		# start our service.
		
		# Initialize the service manager and start our service.
		servicemanager.Initialize()
		servicemanager.PrepareToHostSingle(ExampleService)
		servicemanager.StartServiceCtrlDispatcher()
	
	else:
		# invoked with arguments, or without arguments as a regular
		# Python script
  
		# We support a "help" command that isn't supported by
		# `win32serviceutil.HandleCommandLine` so there's a way for
		# users who run this script from a PyInstaller executable to see
		# help. `win32serviceutil.HandleCommandLine` shows help when
		# invoked with no arguments, but without the following that would
		# never happen when this script is run from a PyInstaller
		# executable since for that case no-argument invocation is handled
		# by the `if` block above.
		if len(sys.argv) == 2 and sys.argv[1] == 'help':
			sys.argv = sys.argv[:1]
			 
		win32serviceutil.HandleCommandLine(ExampleService)


	
def _configure_logging():
	
	formatter = Formatter('%(message)s')
	
	handler = _Handler()
	handler.setFormatter(formatter)
	
	logger = logging.getLogger()
	logger.addHandler(handler)
	logger.setLevel(logging.INFO)
	

class _Handler(Handler):
	def emit(self, record):
		servicemanager.LogInfoMsg(record.getMessage())
		
	
class ExampleService(win32serviceutil.ServiceFramework):
	
	
	_svc_name_ = 'CameraService'
	_svc_display_name_ = 'Camera Service'
	_svc_description_ = 'Example of a Windows service implemented in Python.'
 
 
	def __init__(self, args):
		win32serviceutil.ServiceFramework.__init__(self, args)
		self._stop_event = win32event.CreateEvent(None, 0, 0, None)
 
 
	def GetAcceptedControls(self):
		result = win32serviceutil.ServiceFramework.GetAcceptedControls(self)
		result |= win32service.SERVICE_ACCEPT_PRESHUTDOWN
		return result

	
def SvcDoRun():
	while True:
		# Get the current time
		now = datetime.datetime.now().time()

			# Check if the current time is between 7am and 11pm
		if now >= datetime.time(7, 0) and now < datetime.time(23, 0):
            in_white_list =0
				# Initialize the webcam and face detector
			print("service working")
            FORMAT = '%(asctime)s %(clientip)-15s %(user)-8s %(message)s'
            logging.basicConfig(filename='service.log',format=FORMAT)
            

				# Example log message
			logging.info('CameraService started')
			cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
				
			face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
			face_detected = False
			capture_and_compare = Capture_And_Compare()

			# Loop through each frame from the webcam
			while True:
					# Read the current frame from the webcam
				ret, frame = cap.read()
				
				# Check if the frame was captured successfully
				if not ret:
					continue
				if frame is None:
					continue
					# Convert the frame to grayscale
				gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

				# Detect faces in the grayscale frame using the face detector
				faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5)

					# If faces are detected, set the flag to True
				if len(faces) > 0:
					face_detected = True
				else:
					face_detected = False
						
					# If a face is detected, activate the capture_for_validation function
				if face_detected:
					in_white_list= capture_and_compare.capture_for_validation(frame)
					cv2.imshow('Face Detected!', frame)
				else:
					cv2.imshow('No Face Detected', frame)

					# Exit the loop if the 'q' key is pressed
				if cv2.waitKey(1) & 0xFF == ord('q'):
					break

					# Sleep for a short interval
				time.sleep(0.1)

				# Release the webcam and close all windows
			cap.release()
			cv2.destroyAllWindows()

			# Sleep until the next minute
		time.sleep(60)
        return in_white_list
		
		
	def SvcOtherEx(self, control, event_type, data):
		
		# See the MSDN documentation for "HandlerEx callback" for a list
		# of control codes that a service can respond to.
		#
		# We respond to `SERVICE_CONTROL_PRESHUTDOWN` instead of
		# `SERVICE_CONTROL_SHUTDOWN` since it seems that we can't log
		# info messages when handling the latter.
		
		if control == win32service.SERVICE_CONTROL_PRESHUTDOWN:
			_log('received a pre-shutdown notification')
			self._stop()
		else:
			_log('received an event: code={}, type={}, data={}'.format(
					control, event_type, data))
	

	def _stop(self):
		self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
		win32event.SetEvent(self._stop_event)


	def SvcStop(self):
		self._stop()
 

def _log(fragment):
	message = 'The {} service {}.'.format(ExampleService._svc_name_, fragment)
	logging.info(message)
	
	
if __name__ == '__main__':
	if not pyuac.isUserAdmin():
			print("Re-launching as admin!")
			pyuac.runAsAdmin()
	else:		 
			_main()	# Already an admin here.