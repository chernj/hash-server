import atexit
import socket
import zlib
import hashlib
import datetime
import time
import threading
import os
from multiprocessing import Process, JoinableQueue, Queue, Pipe

def xor_strings(msg, cipher):
	cip_len = len(cipher)
	temp = []
	for i, char in enumerate(msg):
		temp.append(chr(ord(char) ^ ord(cipher[i % cip_len])))
	return ''.join(temp).encode('hex')

def now_ms():
	now = datetime.datetime.now(None)
	return float(str(now.second) + '.' + str(now.microsecond))

def payload_process(payload_q, crc_pipe, end, verbose, key):
	def packet_split(payload):
		result = []
		if len(payload) >= 76:
			pack = ''.join(map(lambda x: x.encode('hex'), payload))
			result.append(pack[0:8])
			result.append(pack[8:16])
			result.append(pack[16:20])
			result.append(pack[20:24])
			result.append(pack[24:-128])
			result.append(int(pack[-128:], 16))
		else:
			print "PACKET IS NOT STRUCTURALLY VALID, TOO SMALL, MISSING INFORMATION"
			return None
		return result
	
	count = 0
	exp = int(key[:6], 16)
	mod = int(key[6:], 16)
	
	while True:
		p = payload_q.get()
		if p is None:
			payload_q.close()
			end.get()
			end.task_done()
			break
		packet = packet_split(p)
		if packet is None:
			continue
		message = ''.join(packet[:5]).decode('hex')
		packet[0] = int(packet[0], 16)
		packet[1] = int(packet[1], 16)
		hash = hashlib.sha256(message)
		x = ('%08X' % (pow(packet[5], exp, mod))).lower()
		if x[-64:] != hash.hexdigest():
			writing.put((0, now_ms(), hex(packet[0]), str(packet[1]), str(hash.hexdigest()), x[-64:]))
			if verbose:
				print "Packet no. " + str(count) + " failed digital signature verification"
		else:
			unpacked = xor_strings(packet[4].decode('hex'), packet[2].decode('hex'))
			unpacked = [unpacked[i:i+8] for i in range(0, len(unpacked), 8)]
			try:
				crc_pipe.send({"id": packet[0],
						"seq_start": packet[1], 
						"length": packet[3], 
						"checksums": unpacked})
			except IOError:
				break
		count += 1

def checksum_calc(comm_pipe, write_q, files, verb):
	def crc32(data, iter=None):
		tmp = ""
		if iter is None:
			tmp = zlib.crc32(data) & 0xFFFFFFFF
		else:
			tmp = zlib.crc32(data, int(iter, 16)) & 0xFFFFFFFF
		return ("%08X" % tmp).lower()
	
	def lookup(id, index, one_more=True):
		if index == 0:
			return crc32(files[id], None)
		if index in bookshelf[id]:
			if one_more:
				return crc32(files[id], bookshelf[id].pop(index, None)["crc"])
			return bookshelf[id].pop(index, None)
		return None
	
	def figure_out(id, batch):
		if len(batch) > 1:
			for myst in files[-1]:
				successes = -1
				with open(myst, "rb") as maybe:
					expected = batch[0]
					for crc in batch:
						if crc == expected:
							successes += 1
						expected = crc32(maybe.read(), expected)
				if successes > 0:
					existing = files.items()
					for k, v in existing:
						if k != -1:
							if myst == v:
								id = k
								break
					files[id] = open(myst, "rb").read()
					bookshelf[id] = {}
					files[-1].remove(myst)
			return id
		else:
			return None
	
	def run_through(packet, overflow):
		id = packet["id"]
		checks = packet["checksums"]
		start = packet["seq_start"]
		if id not in files:
			id = figure_out(id, checks)
			if id is None:
				return overflow
		if overflow > 0:
			start += (4294967296) * overflow
		if start + len(checks) > 4294967295 * (overflow + 1):
			overflow += 1
		tentative = False
		expected = lookup(id, start)
		if expected is None:
			expected = checks[0]
			bookshelf[id][start] = {"missing": True, "crc": expected}
			tentative = True
		seq_no = start
		for chksum in checks:
			if expected != chksum:
				if tentative:
					bookshelf[id][start]["double_check"] = packet
					break
				else:
					if verb:
						print "Packet with sequence start " + str(start) + " failed checksum at " + str(seq_no)
					write_q.put((1, now_ms(), hex(id), str(start), str(seq_no), chksum, expected))
			if chksum != checks[-1]:
				expected = crc32(files[id], expected)
			else:
				seq = seq_no + 1
				patient_crc = lookup(id, seq, False)
				bookshelf[id][seq] = {"missing": False, "crc": expected}
				if patient_crc is not None:
					next = crc32(files[id], expected)
					if "double_check" in patient_crc:
						run_through(patient_crc["double_check"], overflow)
					elif not tentative:
						if next != patient_crc["crc"]:
							if verb:
								print "Verified that packet " + str(seq) + " had an invalid checksum"
							write_q.put((1, now_ms(), hex(id), str(seq), str(seq), patient_crc["crc"], next))
					bookshelf[id].pop(seq, None)
			seq_no += 1
		return overflow
	
	bookshelf = {}
	for place in files.keys():
		if place != -1:
			bookshelf[place] = {}
	overflow = 0
	
	while True:
		packet = comm_pipe.recv()
		overflow = run_through(packet, overflow)

def writer(file_list, write):
	for f in file_list:
		open(f, "w").close()
	
	while True:
		impart = write.get()
		if impart is None:
			write.close()
			break
		diff = impart[1] + .18 - now_ms()
		if diff > 0:
			time.sleep(diff)
		f = open(file_list[impart[0]], "a")
		f.write("\n".join(impart[2:]) + "\n\n")
		f.close()

class ConnectionThread(threading.Thread):
	def __init__(self, ip='127.0.0.1', port=1337):
		threading.Thread.__init__(self)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind((ip, port))
	
	def run(self):
		while True:
			data = self.sock.recv(4096)
			payloads.put(data)

if __name__ == '__main__':
	files = {-1: []}
	ignored = ["config.txt", "checksum_failures.log", "verification_failures.log", "main.py", "payload_dump.bin", "README.md", "send.py"]
	all_files = [f for f in os.listdir('.') if os.path.isfile(f)]
	verbosity = 0
	conf = {}
	if "config.txt" in all_files:
		types = []
		with open("config.txt", "r") as config:
			for line in config:
				if not line.startswith("#") and not line.startswith("\n") and len(line) > 2:
					conf[line.split("=")[0].strip()] = line.split("=")[1].replace(" ", "").rstrip().split(",")
			if "key" not in conf:
				conf["key"] = ["key.bin"]
			ignored.append(conf["key"][0])
			if "verbose" in conf:
				v = conf["verbose"][0].lower()
				if v[0] == 't':
					verbosity = 1
				else:
					verbosity = 0
			if "whitelisted" in conf:
				for val in conf["whitelisted"]:
					if val in ignored:
						ignored.remove(val)
			if "filetypes" in conf:
				for val in conf["filetypes"]:
					types.append(val)
				for f in all_files:
					for t in types:
						if f.endswith(t):
							files[-1].append(f)
			if "files" in conf:
				for f in conf["files"]:
					if ":" in f:
						ready = f.split(":")
						if ready[1] in files[-1]:
							files[-1].remove(ready[1])
						if ready[1] in all_files:
							files[int(ready[0])] = open(ready[1], "rb").read()
	payloads = Queue(maxsize=0)
	ender = JoinableQueue(maxsize=1)
	writing = Queue(maxsize=0)
	
	child, parent = Pipe(False)
	chk = Process(target=checksum_calc, args=(child, writing, files, verbosity,))
	chk.daemon = True
	chk.start()
	
	default = ConnectionThread()
	default.daemon = True
	default.start()
	write = threading.Thread(target=writer, args=(("verification_failures.log", "checksum_failures.log"), writing,))
	write.daemon = True
	write.start()
	keytext = open(conf["key"][0], "rb").read().encode('hex')
	parseloads = threading.Thread(target=payload_process, args=(payloads, parent, ender, verbosity, keytext,))
	parseloads.daemon = True
	parseloads.start()
	def killer():
		parent.close()
		child.close()
		payloads.put(None)
		writing.put(None)
		chk.terminate()
		chk.join()
	atexit.register(killer)
	print "Server is now running"
	while True:
		ender.join()