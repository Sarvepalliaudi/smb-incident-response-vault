# smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
# Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
# This specification and dual hardware-software architecture is original work created solely for this application.
# B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
# Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
# Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
# Intern ID DEV-CRAFT-BQ2VPH | Task 7: Incident Response Plan.
# https://devcraft.fennark.xyz | https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
# https://github.com/Sarvepalliaudi
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY LICENSE ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /app/target/release/smb-ir-vault /usr/local/bin/smb-ir-vault
COPY sample_evidence ./sample_evidence
ENV PORT=8080
EXPOSE 8080
USER 10001:10001
CMD ["smb-ir-vault", "serve"]
