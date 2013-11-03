<?php

namespace Tests\Unit;

use Arachne\SecurityAnnotations\Allowed;
use Arachne\SecurityAnnotations\InRole;
use Arachne\SecurityAnnotations\LoggedIn;
use Arachne\SecurityAnnotations\SecurityAnnotationHandler;
use Codeception\TestCase\Test;
use Mockery;
use Mockery\MockInterface;
use Nette\Application\Request;

/**
 * @author Jáchym Toušek
 */
class SecurityAnnotationHandlerTest extends Test
{

	/** @var SecurityAnnotationHandler */
	private $handler;

	/** @var MockInterface */
	private $user;

	/** @var MockInterface */
	private $storage;

	protected function _before()
	{
		$this->storage = Mockery::mock('Nette\Security\IUserStorage');
		$this->user = Mockery::mock('Nette\Security\User', [ $this->storage ]);
		$this->handler = new SecurityAnnotationHandler($this->user);
	}

	public function testAllowedTrue()
	{
		$annotation = new Allowed();
		$annotation->resource = 'resource';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedAuthorizationException
	 * @expectedExceptionMessage Required privilege 'resource / privilege' is not granted.
	 */
	public function testAllowedFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = 'resource';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->user
			->shouldReceive('isAllowed')
			->with('resource', 'privilege')
			->once()
			->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testAllowedThis()
	{
		$annotation = new Allowed();
		$annotation->resource = '$this';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);
		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedAuthorizationException
	 * @expectedExceptionMessage Required privilege 'Test / privilege' is not granted.
	 */
	public function testAllowedThisFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = '$this';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);
		$this->user
			->shouldReceive('isAllowed')
			->with('Test', 'privilege')
			->once()
			->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testAllowedResource()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$entity = Mockery::mock('Nette\Security\IResource');
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->user
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedAuthorizationException
	 * @expectedExceptionMessage Required privilege 'entity / privilege' is not granted.
	 */
	public function testAllowedResourceFalse()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$entity = Mockery::mock('Nette\Security\IResource');
		$entity
			->shouldReceive('getResourceId')
			->once()
			->andReturn('entity');
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->user
			->shouldReceive('isAllowed')
			->with($entity, 'privilege')
			->once()
			->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Missing parameter '$entity' in given request.
	 */
	public function testAllowedWrongParameter()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$request = new Request('Test', 'GET', []);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\InvalidArgumentException
	 * @expectedExceptionMessage Parameter '$entity' is not an instance of \Nette\Security\IResource.
	 */
	public function testAllowedMissingParameter()
	{
		$annotation = new Allowed();
		$annotation->resource = '$entity';
		$annotation->privilege = 'privilege';
		$entity = Mockery::mock();
		$request = new Request('Test', 'GET', [
			'entity' => $entity,
		]);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testInRoleTrue()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isInRole directly because it's final
		$this->user
			->shouldReceive('getRoles')
			->withAnyArgs()
			->once()
			->andReturn([ 'role' ]);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedAuthorizationException
	 * @expectedExceptionMessage Role 'role' is required for this request.
	 */
	public function testInRoleFalse()
	{
		$annotation = new InRole();
		$annotation->role = 'role';
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isInRole directly because it's final
		$this->user
			->shouldReceive('getRoles')
			->withAnyArgs()
			->once()
			->andReturn([]);

		$this->handler->checkAnnotation($annotation, $request);
	}

	public function testLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(TRUE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	public function testNotLoggedInTrue()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(FALSE);

		$this->assertNull($this->handler->checkAnnotation($annotation, $request));
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedAuthenticationException
	 * @expectedExceptionMessage User must be logged in for this request.
	 */
	public function testLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(FALSE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\FailedNoAuthenticationException
	 * @expectedExceptionMessage User must not be logged in for this request.
	 */
	public function testNotLoggedInFalse()
	{
		$annotation = new LoggedIn();
		$annotation->flag = FALSE;
		$request = new Request('Test', 'GET', []);

		// can't redefine User::isLoggedIn directly because it's final
		$this->storage
			->shouldReceive('isAuthenticated')
			->withAnyArgs()
			->once()
			->andReturn(TRUE);

		$this->handler->checkAnnotation($annotation, $request);
	}

	/**
	 * @expectedException Arachne\SecurityAnnotations\Exception\InvalidArgumentException
	 */
	public function testUnknownAnnotation()
	{
		$annotation = Mockery::mock('Arachne\Verifier\IAnnotation');
		$request = new Request('Test', 'GET', []);

		$this->handler->checkAnnotation($annotation, $request);
	}

}
