const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client - UPDATE THESE WITH YOUR CREDENTIALS
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

module.exports = async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).json({}, corsHeaders);
  }

  // Set CORS headers for all responses
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  try {
    const path = req.url.split('?')[0];
    
    // Route handling
    if (req.method === 'POST' && path === '/api/register') {
      return await handleRegister(req, res);
    } else if (req.method === 'POST' && path === '/api/login') {
      return await handleLogin(req, res);
    } else if (req.method === 'GET' && path === '/api/prompts') {
      return await handleGetPrompts(req, res);
    } else if (req.method === 'GET' && path === '/api/prompts/pending') {
      return await handleGetPendingPrompts(req, res);
    } else if (req.method === 'POST' && path === '/api/prompts') {
      return await handleCreatePrompt(req, res);
    } else if (req.method === 'PUT' && path.startsWith('/api/prompts/')) {
      return await handleUpdatePrompt(req, res);
    } else if (req.method === 'DELETE' && path.startsWith('/api/prompts/')) {
      return await handleDeletePrompt(req, res);
    } else if (req.method === 'GET' && path === '/api/admin/stats') {
      return await handleAdminStats(req, res);
    } else if (req.method === 'GET' && path === '/api/stats') {
      return await handlePublicStats(req, res);
    } else if (req.method === 'POST' && path === '/api/admin/prompts/bulk-action') {
      return await handleBulkAction(req, res);
    } else if (req.method === 'GET' && path === '/') {
      return res.status(200).json({ message: 'PromptZen API is running!', status: 'success' });
    } else {
      return res.status(404).json({ error: 'Route not found' });
    }
  } catch (error) {
    console.error('Server error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

// JWT simple implementation for demo
const jwt = {
  sign: (payload, secret) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = require('crypto')
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  },
  verify: (token, secret) => {
    const [encodedHeader, encodedPayload, signature] = token.split('.');
    const expectedSignature = require('crypto')
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    
    if (signature !== expectedSignature) {
      throw new Error('Invalid token');
    }
    
    return JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
  }
};

const JWT_SECRET = process.env.JWT_SECRET || '484848484848484848484848484848484848484884848swkjhdjwbjhjdh3djbjd3484848484848484';

// Password hashing
const bcrypt = {
  hash: (password) => {
    return require('crypto').createHash('sha256').update(password).digest('hex');
  },
  compare: (password, hash) => {
    return require('crypto').createHash('sha256').update(password).digest('hex') === hash;
  }
};

// Auth middleware
const authenticateToken = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('No token provided');
  }
  
  const token = authHeader.split(' ')[1];
  return jwt.verify(token, JWT_SECRET);
};

// Route handlers
async function handleRegister(req, res) {
  const { username, password } = await parseBody(req);
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  // Validate username
  if (!username.match(/^[a-zA-Z0-9]{3,20}$/)) {
    return res.status(400).json({ error: 'Username must be 3-20 alphanumeric characters' });
  }
  
  // Validate password
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }
  
  // Check if user exists
  const { data: existingUser } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single();
  
  if (existingUser) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  // Create user
  const hashedPassword = bcrypt.hash(password);
  const { data: newUser, error } = await supabase
    .from('users')
    .insert([
      {
        username,
        password: hashedPassword,
        role: 'user',
        created_at: new Date().toISOString()
      }
    ])
    .select()
    .single();
  
  if (error) {
    return res.status(500).json({ error: 'Failed to create user' });
  }
  
  // Create token
  const token = jwt.sign(
    { username: newUser.username, role: newUser.role },
    JWT_SECRET
  );
  
  return res.status(201).json({
    access_token: token,
    username: newUser.username,
    role: newUser.role,
    message: 'Registration successful'
  });
}

async function handleLogin(req, res) {
  const { username, password } = await parseBody(req);
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  // Get user
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single();
  
  if (error || !user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Check password
  if (!bcrypt.compare(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Create token
  const token = jwt.sign(
    { username: user.username, role: user.role },
    JWT_SECRET
  );
  
  return res.json({
    access_token: token,
    username: user.username,
    role: user.role,
    message: 'Login successful'
  });
}

async function handleGetPrompts(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const publicOnly = url.searchParams.get('public') !== 'false';
  
  let query = supabase.from('prompts').select('*');
  
  if (publicOnly) {
    query = query.eq('accepted', true);
  }
  
  const { data: prompts, error } = await query.order('created_at', { ascending: false });
  
  if (error) {
    return res.status(500).json({ error: 'Failed to fetch prompts' });
  }
  
  return res.json(prompts || []);
}

async function handleGetPendingPrompts(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { data: prompts, error } = await supabase
      .from('prompts')
      .select('*')
      .eq('accepted', false)
      .order('created_at', { ascending: false });
    
    if (error) {
      return res.status(500).json({ error: 'Failed to fetch pending prompts' });
    }
    
    return res.json(prompts || []);
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleCreatePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    const body = await parseBody(req);
    
    const { title, tagline, model, text, image_url } = body;
    
    if (!title || !tagline || !model || !text) {
      return res.status(422).json({ error: 'All fields are required' });
    }
    
    const newPrompt = {
      username: user.username,
      title,
      tagline,
      model,
      text,
      image_url: image_url || null,
      accepted: user.role === 'admin',
      "isTrending": false,  // Fixed: added quotes
      created_at: new Date().toISOString()
    };
    
    const { data: prompt, error } = await supabase
      .from('prompts')
      .insert([newPrompt])
      .select()
      .single();
    
    if (error) {
      return res.status(500).json({ error: 'Failed to create prompt' });
    }
    
    return res.status(201).json(prompt);
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleUpdatePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const promptId = req.url.split('/').pop();
    const updates = await parseBody(req);
    
    // If updating isTrending, make sure to use quotes
    if (updates.isTrending !== undefined) {
      updates["isTrending"] = updates.isTrending;
      delete updates.isTrending;
    }
    
    const { data: prompt, error } = await supabase
      .from('prompts')
      .update(updates)
      .eq('id', promptId)
      .select()
      .single();
    
    if (error) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    return res.json(prompt);
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleDeletePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const promptId = req.url.split('/').pop();
    
    const { error } = await supabase
      .from('prompts')
      .delete()
      .eq('id', promptId);
    
    if (error) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    return res.json({ message: 'Prompt deleted successfully' });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleAdminStats(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { data: prompts } = await supabase.from('prompts').select('*');
    const { data: users } = await supabase.from('users').select('username');
    
    const totalPrompts = prompts?.length || 0;
    const acceptedPrompts = prompts?.filter(p => p.accepted)?.length || 0;
    const pendingPrompts = prompts?.filter(p => !p.accepted)?.length || 0;
    const trendingPrompts = prompts?.filter(p => p["isTrending"] && p.accepted)?.length || 0; // Fixed
    const totalUsers = new Set(prompts?.map(p => p.username) || []).size;
    
    return res.json({
      total_prompts: totalPrompts,
      accepted_prompts: acceptedPrompts,
      pending_prompts: pendingPrompts,
      trending_prompts: trendingPrompts,
      total_users: totalUsers
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handlePublicStats(req, res) {
  const { data: prompts } = await supabase
    .from('prompts')
    .select('*')
    .eq('accepted', true);
  
  const acceptedPrompts = prompts || [];
  const uniqueUsers = new Set(acceptedPrompts.map(p => p.username));
  const trendingPrompts = acceptedPrompts.filter(p => p["isTrending"]); // Fixed
  
  return res.json({
    total_prompts: acceptedPrompts.length,
    total_users: uniqueUsers.size,
    trending_prompts: trendingPrompts.length,
    categories: 12
  });
}

async function handleBulkAction(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { prompt_ids, action } = await parseBody(req);
    
    if (!prompt_ids || !Array.isArray(prompt_ids) || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    
    let result;
    if (action === 'approve') {
      result = await supabase
        .from('prompts')
        .update({ accepted: true })
        .in('id', prompt_ids);
    } else if (action === 'reject') {
      result = await supabase
        .from('prompts')
        .delete()
        .in('id', prompt_ids);
    }
    
    if (result.error) {
      return res.status(500).json({ error: 'Failed to process bulk action' });
    }
    
    return res.json({
      message: `Successfully ${action}d ${prompt_ids.length} prompts`,
      updated_count: prompt_ids.length
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helper function to parse request body
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}
