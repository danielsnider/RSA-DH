#!/usr/bin/python
# 
# Copyright 2010 Daniel Snider
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

""" A GUI to compute the parameters of RSA and encrypt and decrypt short messages, and compute a Diffie-Hellman key pair.
Dependencies: wx
Command line: ./RSA-DH.py
"""

import wx 
import time, random, fractions, math

#tests "k" times if a number "a" is prime using fermat's little theorem: for a, if a^n-1 mod n = 1 then a is probably prime
def testprime(n, tests):
	#test if a number is prime
	a = random.randint(1, n-1)
	
	test =  (a ** (n-1)) % n
	
	if tests == 1 and test == 1:
		return True
	elif test != 1: 
		return False
	else: 
		return testprime (n, tests-1)

def genprime(lowerbound, upperbound, tests):
	a = random.randint(lowerbound, upperbound)
		
	while testprime(a, tests) == False:
		a = random.randint(lowerbound, upperbound)
	
	return a
	
def divide(a, b):
	q = int(a/b)
	r = a % b
	return(q,r)

def euclidGCD(a, b):
	if (b == 0):
		return a
	else:
		return euclidGCD(b, a % b)
	
def extendedGCD(a,b):
	if (b == 0):
		return(1,0)
	else:
		(q, r) = divide(a, b)
		(s, t) = extendedGCD(b, r)
		return (t, s - q * t)

class RSAPanel(wx.Panel):
	def __init__(self, parent):
		self.p = None
		self.q = None
		self.n = None
		self.pubK = None
		self.privK = None
		self.m = None
		self.c = None
		self.tests = 840
		self.lowerbound = 100#1
		self.upperbound = 499#9
		
		wx.Panel.__init__(self, parent)
		
		self.quote1 = wx.StaticText(self, label="1. Generate primes p and q ( 100 < p,q < 500)", pos=(10, 10))
		self.button1 = wx.Button(self, label="Generate", pos=(250, 5))
		self.box1 = wx.TextCtrl(self, pos=(330,6), style=wx.TE_READONLY, size=(140,-1))
		self.Bind(wx.EVT_BUTTON, self.genPrimesClick, self.button1)
		
		self.quote2 = wx.StaticText(self, label="2. Compute n=pq", pos=(10, 40))
		self.button2 = wx.Button(self, label="Compute", pos=(105, 35))
		self.box2 = wx.TextCtrl(self, pos=(185,36), style=wx.TE_READONLY|wx.TE_RICH2, size=(140,-1))
		self.Bind(wx.EVT_BUTTON, self.compNClick, self.button2)
		
		self.quote3 = wx.StaticText(self, label="3. Set a public key e = ", pos=(10, 70))
		self.button3 = wx.Button(self, label="Check", pos=(265, 65))
		self.box3 = wx.TextCtrl(self, pos=(122,66), style=wx.TE_RICH2, size=(140,-1))
		self.Bind(wx.EVT_BUTTON, self.checkE, self.button3)
		
		self.quote4 = wx.StaticText(self, label="4. Calculate the private key d", pos=(10, 100))
		self.button4 = wx.Button(self, label="Calculate", pos=(163, 95))
		self.box4 = wx.TextCtrl(self, pos=(245,96), style=wx.TE_READONLY|wx.TE_RICH2, size=(150,-1))
		self.quote42 = wx.StaticText(self, label=" ", pos=(340, 100))
		self.Bind(wx.EVT_BUTTON, self.calcPrivK, self.button4)
		
		self.quote5 = wx.StaticText(self, label="5. Input message m = ", pos=(10, 130))
		self.box5 = wx.TextCtrl(self, pos=(122,126), style=wx.TE_RICH2, size=(140,-1))
		
		self.quote6 = wx.StaticText(self, label="6. Encrypt message ", pos=(10, 160))
		self.button6 = wx.Button(self, label="Encrypt", pos=(110, 155))
		self.box6 = wx.TextCtrl(self, pos=(191,156), style=wx.TE_READONLY|wx.TE_RICH2, size=(220,-1))
		self.Bind(wx.EVT_BUTTON, self.RSAencrypt, self.button6)
		
		self.quote7 = wx.StaticText(self, label="7. Decrypt message ", pos=(10, 190))
		self.button7 = wx.Button(self, label="Decrypt", pos=(110, 185))
		self.box7 = wx.TextCtrl(self, pos=(191,186), style=wx.TE_READONLY|wx.TE_RICH2, size=(220,-1))
		self.Bind(wx.EVT_BUTTON, self.RSAdecrypt, self.button7)
		
	def genPrimesClick(self,event):
		self.p = genprime(self.lowerbound, self.upperbound, self.tests)
		self.q = genprime(self.lowerbound, self.upperbound, self.tests)
		
		result_text = "p = " + str(self.p) + " and q = " + str(self.q)
		self.box1.Clear()
		self.box2.Clear()
		self.box3.Clear()
		self.box4.Clear()
		self.box5.Clear()
		self.box6.Clear()
		self.box7.Clear()
		self.box1.write(result_text)
		
	def checkE(self,event):
		self.pubK = self.box3.GetValue().decode()
		try:
			self.pubK = int(self.pubK)
		except Exception: pass
		
		if "int" not in str(type(self.pubK)) or self.p == None or self.q == None :
			result_text = "Error: generate p, q, e first"
			self.box3.Clear()
			self.box3.SetStyle(0, 999, wx.TextAttr("red"))
			self.box3.write(result_text)
		elif  (euclidGCD(self.pubK, (self.p - 1) * (self.q - 1))) != 1:
			result_text = "Error: e invalid!"
			self.box3.Clear()
			self.box3.SetStyle(0, 999, wx.TextAttr("red"))
			self.box3.write(result_text)
		else:
			self.box3.SetStyle(0, 999, wx.TextAttr("green"))
		
	def compNClick(self,event):
		if self.p == None or self.q == None :
			result_text = "Error: generate p, q first"
			self.box2.Clear()
			self.box2.SetStyle(0, 999, wx.TextAttr("red"))
			self.box2.write(result_text)
		else:
			self.n = self.p * self.q
			result_text = "n = " + str(self.n)
			self.box2.Clear()
			self.box2.write(result_text)
			
	def calcPrivK(self,event):		
		self.pubK = self.box3.GetValue().decode()
		try:
			self.pubK = int(self.pubK)
		except Exception: pass
		
		if self.p == None or self.q == None or "int" not in str(type(self.pubK)):
			result_text = "Error: generate p, q, e first"
			self.box4.Clear()
			self.box4.SetStyle(0, 999, wx.TextAttr("red"))
			self.box4.write(result_text)
		else:
			t = (self.p - 1) * (self.q - 1) #t is short for totient
			inverse = extendedGCD(t, self.pubK)[1]
			if inverse < 0:
				inverse = t + inverse
			self.privK = inverse
			result_text = "d = " + str(self.privK)
			self.box4.Clear()
			self.box4.write(result_text)			
	
	def RSAencrypt(self,event):
		self.m = self.box5.GetValue().decode()
		try:
			self.m = int(self.m)
		except Exception: pass
		if self.n == None or "int" not in str(type(self.m)) or "int" not in str(type(self.pubK)):
			result_text = "Error: generate m, e, n first"
			self.box6.Clear()
			self.box6.SetStyle(0, 999, wx.TextAttr("red"))
			self.box6.write(result_text)
		else:
			self.c = (self.m ** self.pubK) % self.n
			result_text = "c = " + str(self.c)
			self.box6.Clear()
			self.box6.write(result_text)
			
	def RSAdecrypt(self,event):
		if self.n == None or self.c == None or self.privK == None:
			result_text = "Error: generate n, c, privK first"
			self.box7.Clear()
			self.box7.SetStyle(0, 999, wx.TextAttr("red"))
			self.box7.write(result_text)
		elif self.m >= self.n:
			result_text = "Error: m too large. must be smaller than n"
			self.box7.Clear()
			self.box7.SetStyle(0, 999, wx.TextAttr("red"))
			self.box7.write(result_text)
		else:
			recoverM = (self.c ** self.privK) % self.n
			result_text = "m = " + str(recoverM)
			self.box7.Clear()
			self.box7.write(result_text)
			
class DHPanel(wx.Panel):
	def __init__(self, parent):
		self.p = 65537
		self.g = 3
		self.privY = None
		self.pubY = None
		self.privX = None
		self.pubX = None
		self.sessionK1 = None 
		self.sessionK2 = None 
			
		wx.Panel.__init__(self, parent)
		
		self.quote1 = wx.StaticText(self, label="0. Given a large prime p=65537, a primary root g=3", pos=(10, 10))
		
		self.quote2 = wx.StaticText(self, label="1. Choose a random private key x", pos=(10, 40))
		self.quote21 = wx.StaticText(self, label="x = ", pos=(268, 40))
		self.button2 = wx.Button(self, label="Pick Random", pos=(178, 35))
		self.box2 = wx.TextCtrl(self, pos=(289,36), size=(140,-1))
		self.Bind(wx.EVT_BUTTON, self.pickX, self.button2)
		
		self.quote3 = wx.StaticText(self, label="2. Compute the corrosponding public key X", pos=(10, 70))
		self.button3 = wx.Button(self, label="Calculate", pos=(240, 65))
		self.box3 = wx.TextCtrl(self, pos=(320,66), style=wx.TE_READONLY|wx.TE_RICH2, size=(150,-1))
		self.Bind(wx.EVT_BUTTON, self.calcPubX, self.button3)
		
		self.quote4 = wx.StaticText(self, label="3. Choose a random private key y", pos=(10, 100))
		self.quote41 = wx.StaticText(self, label="y = ", pos=(268, 100))
		self.button4 = wx.Button(self, label="Pick Random", pos=(178, 95))
		self.box4 = wx.TextCtrl(self, pos=(289, 96), size=(140,-1))
		self.Bind(wx.EVT_BUTTON, self.pickY, self.button4)
		
		self.quote5 = wx.StaticText(self, label="4. Compute the corrosponding public key Y", pos=(10, 130))
		self.button5 = wx.Button(self, label="Calculate", pos=(225, 125))
		self.box5 = wx.TextCtrl(self, pos=(305, 126), style=wx.TE_READONLY|wx.TE_RICH2, size=(150,-1))
		self.Bind(wx.EVT_BUTTON, self.calcPubY, self.button5)
		
		self.quote6 = wx.StaticText(self, label="5. Calculate the session key", pos=(10, 160))
		self.button6 = wx.Button(self, label="Calculate", pos=(150, 155))
		self.box6 = wx.TextCtrl(self, pos=(230,156), style=wx.TE_RICH2, size=(170,-1))
		self.box7 = wx.TextCtrl(self, pos=(230,179), style=wx.TE_RICH2, size=(170,-1))
		self.Bind(wx.EVT_BUTTON, self.calcSessionK, self.button6)		

	def pickX(self,event):
		self.privX = random.randint(1, self.p-1)
		result_text = str(self.privX)
		self.box2.Clear()
		self.box3.Clear()
		self.box6.Clear()
		self.pubX = None
		self.sessionK = None
		self.box2.write(result_text)
		
	def pickY(self,event):
		self.privY = random.randint(1, self.p-1)
		result_text = str(self.privY)
		self.box4.Clear()
		self.box5.Clear()
		self.box6.Clear()
		self.pubY = None
		self.sessionK = None
		self.box4.write(result_text)
	
	def calcPubX(self,event):		
		self.privX = self.box2.GetValue().decode()
		try:
			self.privX = int(self.privX)
		except Exception: pass
		
		if "int" not in str(type(self.privX)):
			result_text = "Error: choose x first"
			self.box3.Clear()
			self.box3.SetStyle(0, 999, wx.TextAttr("red"))
			self.box3.write(result_text)
		else:
			self.pubX = (self.g ** self.privX) % self.p
			result_text = "X = " + str(self.pubX)
			self.box3.Clear()
			self.box3.write(result_text)	
			
	def calcPubY(self,event):		
		self.privY = self.box4.GetValue().decode()
		try:
			self.privY = int(self.privY)
		except Exception: pass
		
		if "int" not in str(type(self.privY)):
			result_text = "Error: choose x first"
			self.box5.Clear()
			self.box5.SetStyle(0, 999, wx.TextAttr("red"))
			self.box5.write(result_text)
		else:
			self.pubY = (self.g ** self.privY) % self.p
			result_text = "Y = " + str(self.pubY)
			self.box5.Clear()
			self.box5.write(result_text)	
						
	def calcSessionK(self,event):
		if self.pubX == None or self.pubY == None or "int" not in str(type(self.privX)) or "int" not in str(type(self.privY)):
			result_text = "Error: generate x, X, y, Y, first"
			self.box6.Clear()
			self.box6.SetStyle(0, 999, wx.TextAttr("red"))
			self.box6.write(result_text)
		else:
			self.sessionK = (self.pubY ** self.privX) % self.p
			result_text = "K = " + str(self.sessionK) 
			self.sessionK2 = (self.pubX ** self.privY) % self.p
			result_text2 = "K = " + str(self.sessionK) 
			self.box6.Clear()
			self.box6.write(result_text)
			self.box7.Clear()
			self.box7.write(result_text2)

app = wx.App(False)
frame = wx.Frame(None, title="Crypto Final Project", size=(500,270))
nb = wx.Notebook(frame)
nb.AddPage(RSAPanel(nb), "RSA")
nb.AddPage(DHPanel(nb), "Diffie-Hellman")
frame.Show()
app.MainLoop()