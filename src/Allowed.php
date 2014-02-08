<?php

/**
 * This file is part of the Arachne
 *
 * Copyright (c) Jáchym Toušek (enumag@gmail.com)
 *
 * For the full copyright and license information, please view the file license.md that was distributed with this source code.
 */

namespace Arachne\SecurityAnnotations;

use Arachne\Verifier\IRule;
use Nette\Object;

/**
 * @author Jáchym Toušek
 *
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class Allowed extends Object implements IRule
{

	/** @var string */
	public $resource;

	/** @var string */
	public $privilege;

}