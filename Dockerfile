FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY voucher_service ./voucher_service
RUN pip install --no-cache-dir .
# Mount the operator key, policy, and database under /data.  Never bake the key in.
ENV OPERATOR_KEY_PATH=/data/operator.key.pem \
    POLICY_PATH=/data/policy.yaml \
    DATABASE_URL=sqlite:////data/vouchers.db
EXPOSE 8100
CMD ["uvicorn", "--factory", "voucher_service.main:create_app_from_env", "--host", "0.0.0.0", "--port", "8100"]
