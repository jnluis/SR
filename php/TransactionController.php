<?php 

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Services\TransactionProcessor;

class TransactionController extends Controller {
    private $processor;

    public function __construct(TransactionProcessor $processor) {
        $this->processor = $processor;
    }

    public function process(Request $request) {
        $validated = $request->validate([
            'account_id' => 'required|string',
            'type' => 'required|string',
            'amount' => 'required|numeric',
            'currency' => 'required|string|size:3',
            'notes' => 'sometimes|string',
            'metadata' => 'sometimes|array',
            'region' => 'required|string|size:2',
            'tenant_data' => 'sometimes|json'
        ]);

        return $this->processor->processTransaction($validated);
    }
}