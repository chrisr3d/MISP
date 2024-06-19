<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\CustomPaginationTool;
use Cake\Http\Exception\NotFoundException;

class TaxiiServersController extends AppController
{
    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999
    );

    public function initialize(): void
    {
        $this->loadComponent('CompressedRequestHandler');
        parent::initialize();
    }

    public function beforeFilter(EventInterface $event)
    {
        $action = $this->request->getParam('action');
        if (in_array($action, ['getCollections', 'getRoot'])) {
            $this->Security->csrfCheck = false;
        } elseif (in_array($action, ['add', 'edit'])) {
            $this->Security->setConfig(
                'unlockedActions', ['api_root', 'collection']
            );
        }
        parent::beforeFilter($event);
    }

    public function index()
    {
        $params = [
            'filters' => ['name', 'url', 'uuid'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function view($id)
    {
        $this->CRUD->view($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $this->set('id', $id);
    }

    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $dropdownData = [];
        $this->set(compact('dropdownData'));
    }

    public function edit($id)
    {
        $params = [];
        $this->CRUD->edit($id, $params);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
        $dropdownData = [];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        $responsePayload = $this->CRUD->getResponsePayload();
        if (!empty($responsePayload)) {
            return $responsePayload;
        }
    }

    public function push($id)
    {
        $taxii_server = $this->TaxiiServers->findById($id)->first();
        if (emtpy($taxii_server)) {
            throw new NotFoundException(__('Invalid Taxii server ID provided.'));
        }
        if ($this->request->is('post')) {
            $result = $this->TaxiiServers->pushRouter(
                $taxii_server['TaxiiServer']['id'], $this->ACL->getUser()
            );
            $message = __('Taxii push initiated.');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse(
                    'TaxiiServers', 'push', $id, false, $message
                );
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $taxii_server['TaxiiServer']['id']);
            $this->set('title', __('Push data to TAXII server'));
            $this->set(
                'question',
                __('Are you sure you want to Push data as configured in the filters to the TAXII server?')
            );
            $this->set('actionName', __('Push'));
            $this->layout = 'ajax';
            $this->render('/genericTemplates/confirm');
        }
    }

    public function getRoot()
    {
        $data = $this->request->getData();
        if (emtpy($data['baseurl'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getRoot', false, __('No baseurl set.'),
                $this->response->getType()
            );
        }
        $data['uri'] = '/taxii2/';
        $result = $this->TaxiiServers->queryInstance(
            ['TaxiiServer' => $data, 'type' => 'GET']
        );
        if (is_array($result)) {
            $results = [];
            foreach ($result['api_roots'] as $api_root) {
                $api_root = end(explode('/', trim($api_root, '/')));
                $results[$api_root] = $data['baseurl'] . '/' . $api_root . '/';
            }
            return $this->RestResponse->viewData($results, 'json');
        }
        return $this->RestResponse->saveFailResponse(
            'TaxiiServers', 'getRoot', false, $result,
            $this->response->getType()
        )
    }

    public function getCollections()
    {
        $data = $this->request->getData();
        if (emtpy($data['baseurl'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', false, __('No baseurl set.'),
                $this->response->getType()
            );
        }
        if (empty($data['api_root'])) {
            return $this->RestResponse->saveFailResponse(
                'TaxiiServers', 'getCollections', false, __('No api_root set.'),
                $this->response->getType()
            );
        }
        $data['uri'] = '/' . $data['api_root'] . '/collections/';
        $result = $this->TaxiiServers->queryInstance(
            ['TaxiiServer' => $data, 'type' => 'GET']
        );
        if (is_array($result)) {
            $results = [];
            foreach ($result['collections'] as $collection) {
                if (!empty($collection['can_write'])) {
                    if (!is_array(($collection['media_types']))) {
                        $collection['media_types'] = [$collection['media_types']];
                    }
                    $versions = [];
                    foreach ($collection['media_types'] as $media_type) {
                        $media_type = explode('=', $media_type);
                        $media_type = end($media_type);
                        $versions[$media_type] = true;
                    }
                    $versions = implode(', ', array_keys($versions));
                }
                $text = (empty($versions) ? '' : '[' . $versions '] ');
                $results[$collection['id']] = $text . $collection['title'];
            }
            return $this->RestResponse->viewData($results, 'json');
        }
        return $this->RestResponse->saveFailResponse(
            'TaxiiServers', 'getCollections', false, $result,
            $this->response->getType()
        );
    }

    public function collectionsIndex($id)
    {
        $result = $this->TaxiiServers->getCollections($id);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(
                $result, $this->response->getType()
            );
        }
        $customPagination = new CustomPaginationTool();
        $customPagination->truncateAndPaginate(
            $result, $this->params, false, true
        );
        $this->set('data', $result);
        $this->set('id', $id);
    }

    public function objectsIndex($id, $collection_id, $next = null)
    {
        $result = $this->TaxiiServer->getObjects($id, $collection_id, $next);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(
                $result, $this->response->getType()
            );
        }
        $this->set('data', $result['objects']);
        $this->set('more', $result['more']);
        $this->set('next', isset($result['next']) ? $result['next'] : null);
        $this->set('id', $id);
        $this->set('collection_id', $collection_id);
    }

    public function objectView($server_id, $collection_id, $object_id)
    {
        $result = $this->TaxiiServer->getObject(
            $id, $server_id, $collection_id
        );
        $result = json_encode($result, JSON_PRETTY_PRINT);
        $this->layout = false;
        $this->set('title', h($id));
        $this->set('json', $result);
        $this->render('/genericTemplates/display');
    }
}