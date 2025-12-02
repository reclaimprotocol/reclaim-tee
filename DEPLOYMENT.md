# TEE Deployment Guide

## Prerequisites

### AWS (TEE_K - Nitro)
- AWS account with Nitro Enclave-enabled EC2 instances
- AWS KMS key created in target region
- Docker images pushed to ECR
- IAM role with permissions for KMS, CloudWatch, Secrets Manager
- DNS record pointing to instance
- VSock proxy configured for internet (port 8444) and KMS (port 5000)

### GCP (TEE_T - Confidential Space)
- GCP project with Confidential VM API enabled
- Service account with KMS permissions
- Cloud KMS keyring and key created
- Docker image pushed to GCR
- DNS record pointing to VM
- Firewall rule allowing ports 80, 443

---

## TEE_K Deployment (AWS Nitro)

### 1. Launch EC2 Instance
```bash
aws ec2 run-instances \
    --region <region> \
    --image-id <nitro-enabled-ami> \
    --instance-type c5.xlarge \
    --key-name <keypair-name> \
    --security-group-ids <sg-id> \
    --iam-instance-profile Name=<enclave-role> \
    --enclave-options Enabled=true \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=tee-k-prod}]'
```

### 2. Configure Environment
Create environment file with:
```bash
PLATFORM=nitro
ENCLAVE_MODE=true
ENCLAVE_DOMAIN=your-teek-domain.example.com
PORT=8080
HTTPS_PORT=8443
TEET_URL=wss://your-teet-domain.example.com/teek
KMS_KEY=arn:aws:kms:<region>:<account-id>:key/<key-id>
AWS_REGION=<region>
INTERNET_PORT=8444
KMS_PORT=5000
```

### 3. Build Enclave Image
```bash
nitro-cli build-enclave --docker-uri tee_k:latest --output-file tee_k.eif
```
Save the PCR0 from build output - needed for TEE_T attestation.

### 4. Copy EIF to Instance
```bash
scp -i ~/.ssh/<keypair>.pem tee_k.eif ec2-user@<instance-ip>:~/
```

### 5. Run Enclave
```bash
nitro-cli run-enclave \
  --eif-path tee_k.eif \
  --memory 4096 \
  --cpu-count 2 \
  --enclave-cid 16
```

### 6. Start VSock Proxy
```bash
vsock-proxy 8444 0.0.0.0 443 &
vsock-proxy 5000 kms.<region>.amazonaws.com 443 &
```

---

## TEE_T Deployment (GCP Confidential Space)

### 1. Configure Environment
The container receives environment via instance metadata. Key variables:
```bash
PLATFORM=gcp
ENCLAVE_MODE=true
ENCLAVE_DOMAIN=your-teet-domain.example.com
PORT=8081
HTTPS_PORT=443
GOOGLE_PROJECT_ID=<project-id>
GOOGLE_KMS_LOCATION=us-central1
GOOGLE_KMS_KEYRING=<keyring-name>
GOOGLE_KMS_KEY=<key-name>
EXPECTED_TEEK_PCR0=<teek-pcr0-hash>
```

### 2. Create Confidential VM
```bash
gcloud compute instances create tee-t-prod \
    --zone=us-central1-a \
    --machine-type=n2d-standard-2 \
    --confidential-compute-type=SEV \
    --shielded-secure-boot \
    --maintenance-policy=TERMINATE \
    --service-account=<service-account>@<project-id>.iam.gserviceaccount.com \
    --scopes=cloud-platform \
    --image-family=confidential-space \
    --image-project=confidential-space-images \
    --metadata=^~^tee-image-reference=gcr.io/<project-id>/tee-t:<tag>~tee-restart-policy=Never~tee-container-log-redirect=true~tee-monitoring-memory-enable=true \
    --tags=tee-t
```

### 3. Set TEE_K PCR0 (Attestation)
```bash
gcloud compute instances add-metadata tee-t-prod \
    --zone=us-central1-a \
    --metadata=tee-env-EXPECTED_TEEK_PCR0="<teek-pcr0-hash>"
```

Get the PCR0 from TEE_K enclave:
```bash
nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0'
```

Restart VM to apply:
```bash
gcloud compute instances stop tee-t-prod --zone=us-central1-a
gcloud compute instances start tee-t-prod --zone=us-central1-a
```

### 4. Configure Firewall
```bash
gcloud compute firewall-rules create allow-tee-t \
    --allow=tcp:80,tcp:443 \
    --target-tags=tee-t
```

---

## Environment Variables Reference

| Variable | TEE_K | TEE_T | Description |
|----------|-------|-------|-------------|
| `PLATFORM` | `nitro` | `gcp` | Enclave platform |
| `ENCLAVE_MODE` | `true` | `true` | Enable enclave mode |
| `PORT` | `8080` | `8081` | Internal service port |
| `HTTPS_PORT` | `8443` | `443` | External HTTPS port |
| `ENCLAVE_DOMAIN` | Required | Required | Domain for TLS cert |
| `KMS_KEY` | AWS ARN | - | AWS KMS key ARN |
| `AWS_REGION` | Required | - | AWS region |
| `GOOGLE_PROJECT_ID` | - | Required | GCP project ID |
| `GOOGLE_KMS_LOCATION` | - | Required | GCP KMS location |
| `GOOGLE_KMS_KEYRING` | - | Required | GCP KMS keyring name |
| `GOOGLE_KMS_KEY` | - | Required | GCP KMS key name |
| `TEET_URL` | Required | - | TEE_T WebSocket URL |
| `EXPECTED_TEEK_PCR0` | - | Required | TEE_K attestation hash |

---

## Verification

1. Check TEE_K enclave status: `nitro-cli describe-enclaves`
2. Check TEE_T VM logs: `gcloud compute instances get-serial-port-output tee-t-prod --zone=us-central1-a`
3. Test connectivity: `curl https://<your-teek-domain>/health`

---

## Deployment Order

1. Deploy TEE_T first (without PCR0 initially)
2. Build TEE_K EIF and capture PCR0 from build output
3. Update TEE_T with TEE_K's PCR0 via instance metadata
4. Restart TEE_T to apply the PCR0
5. Both TEEs establish mutual attestation
