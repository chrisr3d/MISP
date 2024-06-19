<?php

namespace App\Model\Table;

use Cake\Validation\Validator;

class TaxiiServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('EncryptedFields', ['fields' => ['authkey']]);
        
    }
}