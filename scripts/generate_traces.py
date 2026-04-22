#!/usr/bin/env python3

"""Generate sample OpenTelemetry traces for Elastic APM."""

import argparse
import random
import time

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import Status, StatusCode
except ImportError as exc:
    raise SystemExit(
        "Missing OpenTelemetry dependencies. Run `pip install -r requirements.txt` "
        "and try again."
    ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic traces for the SSD observability pipeline.",
    )
    parser.add_argument(
        "--endpoint",
        default="http://localhost:8200/v1/traces",
        help="OTLP HTTP endpoint for traces.",
    )
    parser.add_argument(
        "--service-name",
        default="ssd-observability-demo",
        help="Service name shown in APM.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=40,
        help="Number of traces to generate.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="Delay in seconds between traces.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Exporter timeout in seconds.",
    )
    return parser.parse_args()


def build_tracer(endpoint: str, service_name: str, timeout: int):
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.namespace": "ssd-project",
            "deployment.environment": "local",
        }
    )

    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=endpoint, timeout=timeout)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    tracer = trace.get_tracer("ssd.observability.traces")
    return provider, tracer


def run_trace(tracer, batch_id: int):
    with tracer.start_as_current_span("pipeline.scan_to_report") as root:
        root.set_attribute("pipeline.batch_id", batch_id)
        root.set_attribute("pipeline.name", "sast_to_defectdojo")
        root.set_attribute("integration.logs", "docker")
        root.set_attribute("integration.feed", "cisa-kev")

        with tracer.start_as_current_span("stage.sast_scan") as scan_span:
            scan_span.set_attribute("toolset", "bandit,njsscan,flawfinder")
            time.sleep(random.uniform(0.03, 0.12))

        with tracer.start_as_current_span("stage.import_defectdojo") as import_span:
            import_span.set_attribute("api", "/api/v2/import-scan/")
            time.sleep(random.uniform(0.04, 0.16))

        with tracer.start_as_current_span("stage.observability_ingest") as ingest_span:
            ingest_span.set_attribute("logs_pipeline", "filebeat-logstash-elasticsearch")
            ingest_span.set_attribute("metrics_pipeline", "metricbeat-elasticsearch")
            time.sleep(random.uniform(0.02, 0.08))

        if random.random() < 0.08:
            root.set_status(Status(StatusCode.ERROR, "simulated timeout during import"))
        else:
            root.set_status(Status(StatusCode.OK))


def main() -> int:
    args = parse_args()
    provider, tracer = build_tracer(args.endpoint, args.service_name, args.timeout)

    print(f"[INFO] Sending {args.count} traces to {args.endpoint}")

    for i in range(1, args.count + 1):
        run_trace(tracer, i)
        if i % 10 == 0 or i == args.count:
            print(f"[INFO] Progress: {i}/{args.count}")
        time.sleep(args.delay)

    provider.force_flush()
    provider.shutdown()

    print("[SUCCESS] Trace generation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
