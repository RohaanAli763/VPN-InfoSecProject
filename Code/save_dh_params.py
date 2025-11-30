from encryption import generate_dh_parameters
from cryptography.hazmat.primitives import serialization

params = generate_dh_parameters()  # 2048-bit secure params
with open("dh_params.pem", "wb") as f:
    f.write(params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ))

print("DH parameters saved to dh_params.pem")
