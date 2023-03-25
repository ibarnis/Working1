
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
import time

class SvcDoRun:
    def __init__(self):
        self.in_white_list = 0

    def is_completed(self):
        if self.in_white_list == 1:
            return self.in_white_list

    def start(self):
        # Get the current time
        now = datetime.datetime.now().time()

        # Check if the current time is between 7am and 11pm
        if now >= datetime.time(7, 0) and now < datetime.time(23, 0):
            # Initialize the webcam and face detector
            print("service working")
            logging.basicConfig(filename='service.log', level=logging.INFO)

            # Example log message
            logging.info('CameraService started')
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            face_detected = False

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

                # If a face is detected, activate the Capture_And_Compare function
                if face_detected:
                    capture = Capture_And_Compare()
                    print(f'Before: in_white_list={self.in_white_list}')
                    self.in_white_list = capture.capturing()
                    print(f'After: in_white_list={self.in_white_list}')

                    # Add logging statement to check if correct value is being set
                    logging.info(f'Setting in_white_list={self.in_white_list}')

                print("in_white_list =", self.in_white_list)
                # Exit the loop if in_white_list is 1
                if self.in_white_list == 1:
                    print(" going to break")
                    break

                # Sleep for a short interval
                time.sleep(0.1)

            # Release the webcam and close all windows
            cap.release()
            cv2.destroyAllWindows()

        return self.in_white_list
