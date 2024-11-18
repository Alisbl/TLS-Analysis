# TLS-Analysis
Analysis of pcap file to provide the services used. The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!
# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!


## Resources
Some resources that will be useful to us when learning about TLS 1.3
*  The Transport Layer Security (TLS) Protocol Version 1.3 [RFC 8446]()
    *  An Interface and Algorithms for Authenticated Encryption [RFC 5116](https://tools.ietf.org/html/rfc5116)
    *  HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869](https://tools.ietf.org/html/rfc5869)
* [TLS 1.3 illustrated](https://tls13.ulfheim.net/)

### Test Endpoint
It takes a pcap file and the code must extrcat the traffic TLS 1.3 from client and server Hello's and gives the services used then using a model it must train and test the pcap so that it must know the service used once the traffic passed
### Helpful snippet
Client:

```bash
python extract_pcap_data.py --input pcap_file.pcap --output extracted_data.csv
python train_classifier.py --input extracted_data.csv --output trained_model.pkl
python predict_service.py --input new_data.csv --model trained_model.pkl --output predictions.csv

```




## Goals
 - [x] Extract the pcap(dataset) parameters for both cient and server .
    - [X] fill the service column that gives the service used
 - [x] make a model that must be trained and tested
    - [X] save the data in pkl file using pickel library
 - [X] The model must predict the service used when a packet was detected again
