CREATE UNIQUE INDEX notification_deliveries_provider_message_lookup
    ON notification_deliveries (provider_binding_key, provider_message_id)
    WHERE provider_binding_key IS NOT NULL
      AND provider_message_id IS NOT NULL;
