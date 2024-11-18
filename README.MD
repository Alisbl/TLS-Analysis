# TLS 1.3
The goal of this project is to better understand TLS 1.3 by creating a pure python implementation. Let's see how this goes!
The goal of this project is to better understand how to train the dataset and extract its services in TLS 1.3 protocol using pcaps by creating a pure python implementation. Let's see how this goes!


## Resources
Some resources that will be useful to us when learning about TLS 1.3
*  The Transport Layer Security (TLS) Protocol Version 1.3 [RFC 8446](https://tools.ietf.org/html/rfc8446)
    *  An Interface and Algorithms for Authenticated Encryption [RFC 5116](https://tools.ietf.org/html/rfc5116)
    *  HMAC-based Extract-and-Expand Key Derivation Function (HKDF) [RFC 5869](https://tools.ietf.org/html/rfc5869)
* [Test for TLS 1.3 Support](https://www.cdn77.com/tls-test)
* [TLS 1.3 illustrated](https://tls13.ulfheim.net/)

### Helpful snippet
Client:

```bash
python extract_pcap_data.py --input pcap_file.pcap --output extracted_data.csv
python train_classifier.py --input extracted_data.csv --output trained_model.pkl
python predict_service.py --input new_data.csv --model trained_model.pkl --output predictions.csv
```

## Goals
 - [x] Exract the parameter from the pcap(dataset).
    - [X] The Extracted Parameters are for both client and server.
- [x] Train and test a model that tarins the parameter SNI.
    - [X] Once the SNI is detected the model must be able to know the service used.
 - [X] give the service used was a packet is detected. 
