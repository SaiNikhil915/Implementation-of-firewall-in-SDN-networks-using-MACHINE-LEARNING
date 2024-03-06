
import ipaddress as IP
import unicodedata
from sklearn.neighbors import NearestNeighbors

def CheckIP(address):
	samples = [[int(IP.ip_address(u'192.168.56.120'))],[int(IP.ip_address(u'192.168.56.200'))],[int(IP.ip_address(u'192.168.56.250'))], [int(IP.ip_address(u'10.0.0.20'))],[int(IP.ip_address(u'10.0.0.30'))], [int(IP.ip_address(u'10.0.0.100'))],[int(IP.ip_address(u'179.168.56.100'))]]


	neigh = NearestNeighbors(n_neighbors=1)
	neigh.fit(samples)


	malicious=(neigh.kneighbors([[int(IP.ip_address(address))]]))
	#print(neigh.kneighbors([[int(IP.ip_address(address))]]))


	#print(malicious[0][0][0])
	testdist=malicious[0][0][0]
	threshold=30


	if(testdist<=threshold):
		#print("Malicious IP detected")
		return -1
	if(testdist==0):
		return 2
	return 1

print(CheckIP(u'10.60.50.47'))

f=open("/home/mohit/networks_ml/github_code/malware.txt","r")
add=f.readline()
add=add.rstrip()
print(CheckIP(str(add)))



# import pandas as pd
# import ipaddress as IP
# from sklearn.neighbors import NearestNeighbors

# def CheckIP(address):
#     # Load your dataset into a pandas DataFrame
#     df = pd.read_csv('/home/mohit/networks_ml/project/combined_dataset.csv')  # Replace 'your_dataset.csv' with the actual file path

#     # Extract IP addresses from the DataFrame
#     samples = [list(map(int, str(ip).split('.'))) for ip in df['IP']]

#     neigh = NearestNeighbors(n_neighbors=1)
#     neigh.fit(samples)

#     malicious = neigh.kneighbors([[int(ip) for ip in address.split('.')]])
#     testdist = malicious[0][0][0]
#     threshold = 30

#     if testdist <= threshold:
#         return -1  # Malicious IP detected
#     if testdist == 0:
#         return 2  # Special case, you can customize this part
#     return 1

# # Example usage
# print(CheckIP(u"10.2.0.150"))

# f=open("/home/mohit/networks_ml/github_code/malware.txt","r")
# add=f.readline()
# add=add.rstrip()
# print(CheckIP(str(add)))

# import pandas as pd
# from sklearn.neighbors import NearestNeighbors

# def CheckIP(address):
#     # Load your dataset into a pandas DataFrame
#     df = pd.read_csv('/home/mohit/networks_ml/project/combined_dataset.csv')  # Replace 'your_dataset.csv' with the actual file path

#     # Extract IP addresses from the DataFrame
#     samples = [list(map(int, str(ip).split('.'))) for ip in df['IP']]

#     neigh = NearestNeighbors(n_neighbors=5)  # Set n_neighbors to a suitable value
#     neigh.fit(samples)

#     # Convert the input IP address to the same format
#     test_ip = [int(ip) for ip in address.split('.')]

#     # Find k-neighbors of a point (use k > 1 to get multiple neighbors)
#     neighbors = neigh.kneighbors([test_ip], return_distance=True)

#     # Extract distances and indices
#     distances, indices = neighbors

#     # Filter neighbors based on distance
#     threshold = 30
#     malicious_neighbors = [df.iloc[idx]['IP'] for dist, idx in zip(distances[0], indices[0]) if dist > threshold]

#     return malicious_neighbors

# # Example usage
# print(CheckIP(u"10.60.50.48"))




