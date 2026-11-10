"""OpenTelemetry tracing, enabled when CTEM_OTEL_EXPORTER_OTLP_ENDPOINT is set."""

from fastapi import FastAPI

from app.core.config import get_settings


def instrument(app: FastAPI) -> None:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    endpoint = get_settings().otel_exporter_otlp_endpoint.rstrip("/") + "/v1/traces"
    provider = TracerProvider(resource=Resource.create({"service.name": "ctem-api"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
