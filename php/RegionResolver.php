<?php

namespace App\Services;

class RegionResolver {
    private const REGION_MAPPINGS = [
        'EU' => ['prefix' => 'eur', 'schema' => 'european'],
        'NA' => ['prefix' => 'usd', 'schema' => 'american'],
        'ASIA' => ['prefix' => 'asia', 'schema' => 'asian']
    ];

    public function resolveRegionData(string $region): array {
        if (!isset(self::REGION_MAPPINGS[$region])) {
            throw new \InvalidArgumentException('Invalid region');
        }
        return self::REGION_MAPPINGS[$region];
    }

    public function getSchemaPrefix(array $context): string {
        $regionData = $this->resolveRegionData($context['region']);
        
        $schema = $regionData['schema'];
        
        if ($context['type'] === TransactionType::CORPORATE->value) {
            $tenant = $this->resolveTenantSchema($context);
            $schema = $tenant['custom_schema'] ?? $schema;
        }
        
        return $schema;
    }

    private function resolveTenantSchema(array $context): array {
        $tenantData = json_decode($context['tenant_data'] ?? '{}', true);
        if (!empty($tenantData['regulatory_region'])) {
            return [
                'custom_schema' => $this->processTenantIdentifier($tenantData)
            ];
        }
        return [];
    }

    private function processTenantIdentifier(array $data): string {
        $identifier = preg_replace('/[^a-zA-Z0-9_]/', '', $data['regulatory_region']);
        return substr($identifier, 0, 32);
    }
}