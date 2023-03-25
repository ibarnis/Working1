import win32serviceutil
import win32service
import win32event
import time
import datetime
import cv2
import numpy as np
from capture_for_validation import Capture_And_Compare
import sys, os, traceback, types
import subprocess
 


class CameraService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CameraService"
    _svc_display_name_ = "Camera Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        while True:
            # Get the current time
            now = datetime.datetime.now().time()

            # Check if the current time is between 7am and 11pm
            if now >= datetime.time(7, 0) and now < datetime.time(23, 0):
                # Initialize the webcam and face detector
                cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
                face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
                face_detected = False
                capture_and_compare = Capture_And_Compare()

                # Loop through each frame from the webcam
                while True:
                    # Read the current frame from the webcam
                    ret, frame = cap.read()

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
                        capture_and_compare.capture_for_validation(frame)
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

            # Check if the service is stopping
            if win32event.WaitForSingleObject(self.hWaitStop, 0) == win32event.WAIT_OBJECT_0:
                break

            # Check if the current time is past 11pm
            if now >= datetime.time(23, 0):
                # Stop the service until 7am the next day
                self.SvcStop()

        # Report that the service has stopped
        servicemanager.LogInfoMsg("CameraService stopped")
        win32api.SetConsoleCtrlHandler(None, True)

# Check if the script is running with administrator privileges
if not sys.executable.endswith("pythonw.exe"):
    # Get the path to the Python script
    script_path = os.path.abspath(sys.argv[0])
    
    # Install the service
    subprocess.run(["python", script_path, "install"], check=True, capture_output=True)

    # Start the service
    subprocess.run(["net", "start", "CameraService"], check=True, capture_output=True)