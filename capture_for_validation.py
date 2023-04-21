from pathlib import Path
from tkinter.messagebox import NO
import cv2
import numpy as np
from facenet_pytorch import MTCNN # pip install facenet-pytorch
from tqdm import tqdm
import torch
from Cords import Cords
from whitelist import insertVaribleIntoTable,main,get_index,add_admin,is_white
from face import Face
from new_rec import get_embeddings
import datetime
import time
import os
import hashlib
import base64
class FastMTCNN(object):
	"""Fast MTCNN implementation."""
	
	def __init__(self, stride, resize=1, *args, **kwargs):
		"""Constructor for FastMTCNN class.
		
		Arguments:
			stride (int): The detection stride. Faces will be detected every `stride` frames
				and remembered for `stride-1` frames.
		
		Keyword arguments:
			resize (float): Fractional frame scaling. [default: {1}]
			*args: Arguments to pass to the MTCNN constructor. See help(MTCNN).
			**kwargs: Keyword arguments to pass to the MTCNN constructor. See help(MTCNN).
		"""
		self.stride = stride
		self.resize = resize
		self.mtcnn = MTCNN(*args, **kwargs)
		
	def __call__(self, frames):
		"""Detect faces in frames using strided MTCNN."""
		if self.resize != 1:
			frames = [
				cv2.resize(f, (int(f.shape[1] * self.resize), int(f.shape[0] * self.resize)))
					for f in frames
			]
					  
		boxes, probs = self.mtcnn.detect(frames[::self.stride])

		return (boxes, probs)


class Capture_And_Compare():
	def __init__(self):
		pass


	def second_passed(self,oldtime):
		if oldtime==None:
			return True
		return time.time() - oldtime >= 0.5
		

	def capturing(self):
		confidence_th = 0.99

		device = 'cuda' if torch.cuda.is_available() else 'cpu'

		FONT = cv2.FONT_HERSHEY_SIMPLEX


		cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)
		if(cap is None):
			print('Camera resource is not available')
			exit(-1)
		width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
		height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
		fps = 24
		highest_conf= 0
		current_conf=0
		begin_time = time.time()
		found_time= begin_time
		bestPic = None
		threshold_conf=0.98
		fourcc = cv2.VideoWriter_fourcc(*'DIVX')

		fast_mtcnn = FastMTCNN(
		stride=4,
		resize=0.5,
		margin=14,
		factor=0.6,
		keep_all=True,
		device=device
		)
		faces =[]
		running_idx = 0
		while(True):
			ret, frame = cap.read(0)
			if(ret == False):
				print('Frame was not fetched')
				exit(-1)
			else:
				print("Filming!")
				running_idx = running_idx + 1
			frames_rgb = []
			
			# detect faces in the image
			frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
			frames_rgb.append(frame_rgb)
			faces_rois, faces_confs = fast_mtcnn(frames_rgb)
			

			for roi, conf in zip(faces_rois, faces_confs):
				
				if(roi is None or conf is None):
					continue
				conf = float(conf[0])
				roi = roi[0]
				x, y, width, height = int(roi[0] + roi[2]/2) , int(roi[1] + roi[3]/2), int(roi[2]), int(roi[3])
				if (self.second_passed(found_time) and conf>=threshold_conf ):
					found_time=time.time()
					cords = Cords(x,y,width,height)
					faces.append(Face(conf,cords,frame))
			
			if (found_time - begin_time >=10) or (current_conf>=0.995) :
				print("MTCNN DONE!")
				break
		cap.release()
		
		white =[]
		found=0
		for face in faces:
			rescaled_frame = face.extract_face()
			print('imHERE!')
			embedings= get_embeddings(rescaled_frame)
			if is_white(embedings):
				white.append(1)
				print("WHITE123!")
			else:
				white.append(0)
		if len(white)>0:
			if ((sum(white))/(len(white))>0.5):
				print("in WHITE!")
				found=1
			print('Finished processing. Release resources.')
		
		cv2.destroyAllWindows()
		print("returning found", found)
		return found
  


