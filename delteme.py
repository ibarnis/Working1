
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
import cv2


def SvcDoRun():
	while True:
		# Get the current time
		now = datetime.datetime.now().time()

			# Check if the current time is between 7am and 11pm
		if now >= datetime.time(7, 0) and now < datetime.time(23, 0):
			in_white_list =0
				# Initialize the webcam and face detector
			print("service working")
			logging.basicConfig(filename='service.log', level=logging.INFO)

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
					
					if in_white_list==1:
					   whitelist_expiration = datetime.datetime.now() + datetime.timedelta(minutes=15)
					   #return that face is found
					   get_in_white_list()
					   logging.info('a user entered')
					   time.sleep(900)
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
		# Check if the whitelist has expired
		if whitelist_expiration is not None and datetime.datetime.now() > whitelist_expiration:
		   whitelist = False
		   whitelist_expiration = None

def get_in_white_list():
	print (in_white_list)
	return str(in_white_list)
   
