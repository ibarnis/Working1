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
from numpy import asarray
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
		print("i am here!")
					  
		boxes, probs = self.mtcnn.detect(frames[::self.stride])

		return (boxes, probs)
		
class FaceFrame():
		def __init__(self, frames):
			if frames is not None:
				self.frames = frames
				device = 'cuda' if torch.cuda.is_available() else 'cpu'
				self.fast_mtcnn = FastMTCNN(
				stride=4,
				resize=0.5,
				margin=14,
				factor=0.6,
				keep_all=True,
				device=device
				)
				

					
				
			else:
				self.frames = []
		
	   
		def is_face_valid(self):
			faces =[]
			threshold_conf=0.98
			
			
			
			# detect faces in the image

			frames_rgb = []
			
			for frame in self.frames:
				# detect faces in the image
				frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
				frames_rgb.append(frame_rgb)
			print("selfMTCNN")
			faces_rois, faces_confs = self.fast_mtcnn(frames_rgb)

			

			for roi, conf in zip(faces_rois, faces_confs):
				
				if(roi is None or conf is None):
					continue
				conf = float(conf[0])
				roi = roi[0]
				x, y, width, height = int(roi[0] + roi[2]/2) , int(roi[1] + roi[3]/2), int(roi[2]), int(roi[3])
				if (conf>=threshold_conf):
					cords = Cords(x,y,width,height)
					faces.append(Face(conf,cords,frame))
		
	
			white =[]
			found=0
			for face in faces:
				rescaled_frame = face.extract_face()
				print('imHERE!')
				embedings= get_embeddings(rescaled_frame)
				is_white_bool,name= is_white(embedings)
				if is_white_bool==True:
					white.append(1)
					print("WHITE123!")
				else:
					white.append(0)
			if len(white)>0:
				if ((sum(white))/(len(white))>0.5):
					print("in WHITE!")
					found=1
				print('Finished processing. Release resources.')
			
		
			print("returning found", found)
			if found==0:
				return found,""
			else:
				return found,name