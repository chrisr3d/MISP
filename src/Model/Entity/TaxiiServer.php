<?php

namespace App\Model\Entity;

use App\Lib\Tools\HttpTool;
// use App\Model\Entity\Event;
use App\Model\Entity\Job;
use Cake\Http\Client\Exception\NetworkException;
use Cake\Http\Exception\BadRequestException;

class TaxiiServer extends AppModel
{
    public function pushRouter($id, $user)
    {
        return $this->push($id, $user);
    }

    public function push($id, $user, $jobId = null)
    {
        
    }

    public function queryInstance($options)
    {
        $server_options = $options['TaxiiServer'];
        $url = $server_options['url'] . $server_options['uri'];
        $httpTool = new HttpTool();
        $request = [
            'header' => [
                'Accept' => 'application/taxii+json;version=2.1',
                'Content-type' => 'application/taxii+json;version=2.1'
            ]
        ];
        if (!empty($server_options['api_key'])) {
            $request['header']['Authorization'] = 'basic ' . $server_options['api_key'];
        }
        try {
            if (!empty($options['type']) && $options['type'] == 'post') {
                $response = $httpTool->post(
                    $url, json_encode($options['body'], $request)
                );
            } else {
                $response = $httpTool->get(
                    $url,
                    (!empty($options['query']) ? $options['query'] : null),
                    $request
                );
            }
            if ($response->isOk()) {
                return json_decode($response->getBody()->__toString(), true);
            }
        } catch (NetworkException $e) {
            throw new BadRequestException(
                __('Something went wrong. Error returned: %s', $e->getMessage())
            );
        }
        if ($response->getStatusCode() === 403 || $response->getStatusCode() === 401) {
            throw new ForbiddenException(__('Authentication failed.'));
        }
        throw new BadRequestException(
            __('Something went wrong with the request or the remote side is having issues.')
        );
    }

    public function getCollections($id)
    {
        $taxii_server = $this->findById($id)->first();
        $taxii_server['TaxiiServer']['uri'] = (
            '/' . $taxii_server['TaxiiServer']['api_root'] . '/collections/';
        );
        $response = $this->queryInstance(
            [
                'TaxiiServer' => $taxii_server['TaxiiServer'],
                'type' => 'GET'
            ]
        );
        if (empty($response['collections'])) {
            throw new BadRequestException(__('No collections found.'));
        }
        return $response['collections'];
    }

    public function getObjects($id, $collection_id = null, $next = null)
    {
        $taxii_server = $this->findById($id)->first();
        if (empty($collection_id)) {
            $collection_id = $taxii_server['TaxiiServer']['collection'];
        }
        $api_root = $taxii_server['TaxiiServer']['api_root'];
        $taxii_server['TaxiiServer']['uri'] = (
            '/' . $api_root . '/collections/' . $collection_id . '/objects/'
        );
        $response = $this->queryInstance(
            [
                'TaxiiServer' => $taxii_server['TaxiiServer'],
                'type' => 'GET',
                'query' => [
                    'limit' => 50,
                    'next' => $next
                ]
            ]
        );
        if (empty($response['objects'])) {
            throw new BadRequestException(
                __('No objects found in collection with the given query parameters.')
            );
        }
        return $response;
    }

    public function getObject($id, $server_id, $collection_id)
    {
        $taxii_server = $this->findById($server_id)->first();
        $api_root = $taxii_server['TaxiiServer']['api_root'];
        $taxii_server['TaxiiServer']['uri'] = (
            '/' . $api_root . '/collections/' . $collection_id . '/objects/' . $id . '/'
        );
        $response = $this->queryInstance(
            [
                'TaxiiServer' => $taxii_server['TaxiiServer'],
                'type' => 'GET'
            ]
        );
        if (empty($response['objects'])) {
            throw new BadRequestException(
                __('Invalid object or object not found in the given collection.')
            );
        }
        return $response['objects'][0];
    }
}