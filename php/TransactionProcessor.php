<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use App\Models\Transaction;

class TransactionProcessor {
    private $regionResolver;
    private $validationService;
    private $complianceService;

    public function __construct(
        RegionResolver $regionResolver,
        ValidationService $validationService,
        ComplianceService $complianceService
    ) {
        $this->regionResolver = $regionResolver;
        $this->validationService = $validationService;
        $this->complianceService = $complianceService;
    }

    public function processTransaction(array $data) {
        try {
            $validated = $this->validationService->validateTransactionData($data);
            
            DB::beginTransaction();

            $schema = $this->regionResolver->getSchemaPrefix([
                'region' => $data['region'],
                'type' => $data['type'],
                'tenant_data' => $data['tenant_data'] ?? null
            ]);

            $accountTable = sprintf('%s.accounts', $schema);
            $account = DB::table($accountTable)
                        ->where('id', $validated['account_id'])
                        ->first();

            if (!$account) {
                throw new \Exception('Account not found');
            }

            if ($validated['type'] === TransactionType::INTERNATIONAL->value) {
                $complianceResult = $this->complianceService
                    ->validateInternationalTransfer($validated);
                
                if ($complianceResult->status === 'compliance_review') {
                    return ['status' => 'compliance_review'];
                }
            }

            $transaction = new Transaction($validated);
            $transaction->status = TransactionStatus::COMPLETED->value;
            $transaction->save();

            $this->updateAccountBalance($account, $validated['amount']);

            DB::commit();
            return ['status' => 'success', 'transaction_id' => $transaction->id];

        } catch (\Exception $e) {
            DB::rollBack();
            throw $e;
        }
    }

    private function updateAccountBalance($account, float $amount): void {
        #exemple
    }
}