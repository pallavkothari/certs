# LetsEncrypt wildcard certs

Using `acme4j` and `hover` at the moment. 

### build
```bash
./gradlew build
```

### run
```bash
export HOVER_USERNAME=<hover_username>
export HOVER_PASSWORD=<hover_password>

# with gradle:
./gradlew run -PappArgs="['--mode','staging','--domain','*.foo.org','--domain','*.bar.foo.org']" 

# or without gradle; use the generated start script in the distro
cd build/distributions 
unzip *.zip 
cd $(ls -d */)
./bin/letsencrypt-wildcard-certs --mode staging --domain *.foo.org --domain *.bar.foo.org
```

### Verify the cert chain
```bash
openssl x509 -in domain-chain.crt -text

```

### Resources
- [acme v2 + wildcard support goes live](https://community.letsencrypt.org/t/acme-v2-and-wildcard-certificate-support-is-live/55579)
- [acme v2 prod endpoint](https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578)
- [acme v2 staging endpoint](https://community.letsencrypt.org/t/staging-endpoint-for-acme-v2/49605/2)
- [client options](https://letsencrypt.org/docs/client-options/)
- [acme4j](https://github.com/shred/acme4j)
- [hover](https://github.com/pallavkothari/hover)