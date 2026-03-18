<?php
/**
 * OtlpParser: parses OpenTelemetry Protocol (OTLP) JSON payloads.
 */
class OtlpParser
{
    /**
     * Parse OTLP JSON data and return an array of normalized span records.
     *
     * @param  array $data Decoded JSON payload
     * @return array[]     Array of span arrays ready for DB insertion
     */
    public static function parse(array $data): array
    {
        $spans = [];

        $resourceSpans = isset($data['resourceSpans']) ? $data['resourceSpans'] : [];

        foreach ($resourceSpans as $resourceSpan) {
            // Extract resource-level attributes (e.g. openrouter.trace.id)
            $resourceAttrs = self::extractAttributes(
                isset($resourceSpan['resource']['attributes'])
                    ? $resourceSpan['resource']['attributes']
                    : []
            );

            $scopeSpans = isset($resourceSpan['scopeSpans']) ? $resourceSpan['scopeSpans'] : [];

            foreach ($scopeSpans as $scopeSpan) {
                $rawSpans = isset($scopeSpan['spans']) ? $scopeSpan['spans'] : [];

                foreach ($rawSpans as $span) {
                    $spans[] = self::normalizeSpan($span, $resourceAttrs);
                }
            }
        }

        return $spans;
    }

    /**
     * Normalize a single span array into a flat DB record.
     *
     * @param  array $span          Raw span from OTLP payload
     * @param  array $resourceAttrs Flattened resource-level attributes
     * @return array
     */
    private static function normalizeSpan(array $span, array $resourceAttrs = []): array
    {
        $traceId = isset($span['traceId']) ? $span['traceId'] : '';
        $spanId  = isset($span['spanId'])  ? $span['spanId']  : '';

        $traceId = self::ensureHex($traceId);
        $spanId  = self::ensureHex($spanId);

        $startNano  = isset($span['startTimeUnixNano']) ? (float) $span['startTimeUnixNano'] : 0.0;
        $endNano    = isset($span['endTimeUnixNano'])   ? (float) $span['endTimeUnixNano']   : 0.0;
        $durationMs = ($startNano > 0 && $endNano > 0)
            ? (int) round(($endNano - $startNano) / 1_000_000)
            : null;
        $startedAt  = $startNano > 0 ? self::nanoToDatetime($startNano) : null;
        $endedAt    = $endNano   > 0 ? self::nanoToDatetime($endNano)   : null;

        $attrs = self::extractAttributes(
            isset($span['attributes']) ? $span['attributes'] : []
        );

        return [
            // Identifiers
            'trace_id'             => $traceId,
            'span_id'              => $spanId,
            'openrouter_trace_id'  => $resourceAttrs['openrouter.trace.id'] ?? null,

            // Model & provider
            'request_model'        => $attrs['gen_ai.request.model']  ?? null,
            'response_model'       => $attrs['gen_ai.response.model'] ?? null,
            'provider_name'        => $attrs['trace.metadata.openrouter.provider_name'] ?? null,
            'provider_slug'        => $attrs['trace.metadata.openrouter.provider_slug'] ?? null,

            // Operation metadata
            'operation_name'       => $attrs['gen_ai.operation.name']        ?? null,
            'span_type'            => $attrs['span.type']                    ?? null,
            'finish_reason'        => $attrs['gen_ai.response.finish_reason']
                                        ?? ($attrs['trace.metadata.openrouter.finish_reason'] ?? null),
            'finish_reasons'       => $attrs['gen_ai.response.finish_reasons'] ?? null,
            'trace_name'           => $attrs['trace.name']                   ?? null,

            // Tokens
            'input_tokens'         => isset($attrs['gen_ai.usage.input_tokens'])
                                        ? (int) $attrs['gen_ai.usage.input_tokens'] : null,
            'output_tokens'        => isset($attrs['gen_ai.usage.output_tokens'])
                                        ? (int) $attrs['gen_ai.usage.output_tokens'] : null,
            'cached_tokens'        => isset($attrs['gen_ai.usage.input_tokens.cached'])
                                        ? (int) $attrs['gen_ai.usage.input_tokens.cached'] : null,
            'reasoning_tokens'     => isset($attrs['gen_ai.usage.output_tokens.reasoning'])
                                        ? (int) $attrs['gen_ai.usage.output_tokens.reasoning'] : null,
            'audio_tokens'         => isset($attrs['gen_ai.usage.input_tokens.audio'])
                                        ? (int) $attrs['gen_ai.usage.input_tokens.audio'] : null,
            'video_tokens'         => isset($attrs['gen_ai.usage.input_tokens.video'])
                                        ? (int) $attrs['gen_ai.usage.input_tokens.video'] : null,
            'image_tokens'         => isset($attrs['gen_ai.usage.output_tokens.image'])
                                        ? (int) $attrs['gen_ai.usage.output_tokens.image'] : null,

            // Cost (USD)
            'input_cost_usd'       => isset($attrs['gen_ai.usage.input_cost'])
                                        ? (float) $attrs['gen_ai.usage.input_cost'] : null,
            'output_cost_usd'      => isset($attrs['gen_ai.usage.output_cost'])
                                        ? (float) $attrs['gen_ai.usage.output_cost'] : null,
            'total_cost_usd'       => isset($attrs['gen_ai.usage.total_cost'])
                                        ? (float) $attrs['gen_ai.usage.total_cost'] : null,
            'input_unit_price'     => isset($attrs['trace.metadata.openrouter.input_unit_price'])
                                        ? (float) $attrs['trace.metadata.openrouter.input_unit_price'] : null,
            'output_unit_price'    => isset($attrs['trace.metadata.openrouter.output_unit_price'])
                                        ? (float) $attrs['trace.metadata.openrouter.output_unit_price'] : null,

            // Timing
            'started_at'           => $startedAt,
            'ended_at'             => $endedAt,
            'duration_ms'          => $durationMs,

            // Input / Output content
            'span_input'           => $attrs['span.input']       ?? null,
            'span_output'          => $attrs['span.output']      ?? null,
            'trace_input'          => $attrs['trace.input']      ?? null,
            'trace_output'         => $attrs['trace.output']     ?? null,
            'gen_ai_prompt'        => $attrs['gen_ai.prompt']    ?? null,
            'gen_ai_completion'    => $attrs['gen_ai.completion'] ?? null,

            // Context
            'api_key_name'         => $attrs['trace.metadata.openrouter.api_key_name'] ?? null,
            'user_id'              => $attrs['trace.metadata.openrouter.creator_user_id']
                                        ?? ($attrs['user_id'] ?? null),
            'entity_id'            => $attrs['trace.metadata.openrouter.entity_id'] ?? null,
        ];
    }

    /**
     * Extract OTLP attributes array into a flat key => value map.
     * Handles stringValue, intValue, doubleValue, boolValue.
     *
     * @param  array $attributes
     * @return array
     */
    public static function extractAttributes(array $attributes): array
    {
        $result = [];

        foreach ($attributes as $attr) {
            $key   = isset($attr['key'])   ? $attr['key']   : null;
            $value = isset($attr['value']) ? $attr['value'] : [];

            if ($key === null) {
                continue;
            }

            if (isset($value['stringValue'])) {
                $result[$key] = (string) $value['stringValue'];
            } elseif (isset($value['intValue'])) {
                $result[$key] = (int) $value['intValue'];
            } elseif (isset($value['doubleValue'])) {
                $result[$key] = (float) $value['doubleValue'];
            } elseif (isset($value['boolValue'])) {
                $result[$key] = (bool) $value['boolValue'];
            }
        }

        return $result;
    }

    /**
     * Convert a Unix nanosecond timestamp to a DATETIME(3) string.
     *
     * @param  float $nano
     * @return string  e.g. "2024-03-10 12:34:56.789"
     */
    private static function nanoToDatetime(float $nano): string
    {
        $ms  = (int) round($nano / 1_000_000);
        $sec = (int) ($ms / 1000);
        $ms3 = str_pad((string) ($ms % 1000), 3, '0', STR_PAD_LEFT);
        return gmdate('Y-m-d H:i:s', $sec) . '.' . $ms3;
    }

    /**
     * Ensure a trace/span ID is hex-encoded.
     * If the string contains non-hex bytes it is treated as binary and converted.
     *
     * @param  string $id
     * @return string
     */
    private static function ensureHex(string $id): string
    {
        if ($id === '') {
            return $id;
        }

        if (preg_match('/^[0-9a-fA-F]+$/', $id)) {
            return strtolower($id);
        }

        return bin2hex($id);
    }
}
